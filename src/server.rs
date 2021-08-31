/**
# Listener sockets for stream connections

Listener sockets for stream connections are generally TCP sockets. They may additionally have a TLS context associated to also transition to TLS right away or to forward the context to connections for later use with STARTTLS.
*/
use mlua::prelude::*;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::{warn, error};

use tokio::select;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::TlsAcceptor;

use crate::with_runtime_lua;
use crate::core::{MAIN_CHANNEL, Message, Spawn};

use crate::tls;

/**
Control if and how TLS is accepted on listener sockets.
*/
#[derive(Clone)]
enum TlsMode {
	/// TLS is never established, but if the `tls_config` is given, it will be forwarded to any created connections for later use with STARTTLS.
	Plain{
		tls_config: Option<TlsAcceptor>,
	},
	/// TLS will always attempted and if it fails, the Lua side will never see the connection.
	DirectTls{
		tls_config: TlsAcceptor,
	},
	/// TLS is established if the first byte on the connection is 0x16 (the TLS handshake start). Otherwise, the connection is handled as plaintext connection.
	///
	/// In case of a plaintext connection, the TLS config is forwarded to the connection socket for later use with STARTTLS.
	Multiplex{
		tls_config: TlsAcceptor,
	},
}

struct UnquotedStr(&'static str);

impl fmt::Debug for UnquotedStr {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.0)
	}
}

impl fmt::Debug for TlsMode {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Plain{tls_config: Some(_)} => {
				f.debug_struct("TlsMode::Plain")
					.field("tls_config", &UnquotedStr("Some(tls_config)"))
					.finish()
			},
			Self::Plain{tls_config: None} => {
				f.debug_struct("TlsMode::Plain")
					.field("tls_config", &UnquotedStr("None"))
					.finish()
			},
			Self::DirectTls{..} => {
				f.debug_struct("TlsMode::DirectTls")
					.finish_non_exhaustive()
			},
			Self::Multiplex{..} => {
				f.debug_struct("TlsMode::Multiplex")
					.finish_non_exhaustive()
			},
		}
	}
}

impl TlsMode {
	async fn accept(&self, handle: &'_ Arc<LuaRegistryKey>, conn: TcpStream, addr: SocketAddr) -> io::Result<Message> {
		match self {
			Self::Plain{..} => {
				Ok(Message::TcpAccept{
					handle: handle.clone(),
					stream: conn,
					addr,
				})
			},
			Self::DirectTls{tls_config} => {
				let conn = tls_config.accept(conn).await?;
				Ok(Message::TlsAccept{
					handle: handle.clone(),
					stream: conn,
					addr,
				})
			},
			Self::Multiplex{tls_config} => todo!(),
		}
	}
}

/**
Messages to control the behaviour of listener sockets.
*/
enum ControlMessage {
	/// Close the listener socket, not accepting any further connections.
	Close,
}

struct ListenerWorker {
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	global_tx: mpsc::Sender<Message>,
	tls_mode: TlsMode,
	sock: TcpListener,
	handle: Arc<LuaRegistryKey>,
}

impl ListenerWorker {
	async fn run(mut self) {
		loop {
			select! {
				msg = self.rx.recv() => match msg {
					Some(ControlMessage::Close) => return,
					None => return,
				},
				conn = self.sock.accept() => match conn {
					Ok((conn, addr)) => {
						let msg = match self.tls_mode.accept(&self.handle, conn, addr).await {
							Ok(msg) => msg,
							Err(e) => {
								warn!("failed to fully accept connection: {}", e);
								continue;
							},
						};
						// we don't care about failure here; this can only fail during shutdown when nobody else cares anymore either.
						let _ = self.global_tx.send(msg).await;
					},
					Err(e) => {
						// TODO: proper logging!
						error!("failed to accept socket: {}. backing off for 5s", e);
						tokio::time::sleep(Duration::new(5, 0)).await;
					},
				},
				// when the global tx queue is gone, we don't need to accept anything anymore and can just go to rest
				_ = self.global_tx.closed() => return,
			}
		}
	}
}

impl Spawn for ListenerWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}

struct ListenerHandle {
	tx: mpsc::UnboundedSender<ControlMessage>,
	// so that we do not need a roundtrip to the worker to discover these when Lua asks
	sockaddr: String,
	sockport: u16,
}

impl LuaUserData for ListenerHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("ip", |_, this: &Self, _: ()| -> LuaResult<String> {
			Ok(this.sockaddr.clone())
		});

		methods.add_method("port", |_, this: &Self, _: ()| -> LuaResult<u16> {
			Ok(this.sockport)
		});

		methods.add_method("clientport", |_, this: &Self, _: ()| -> LuaResult<u16> {
			Ok(this.sockport)
		});

		methods.add_method("serverport", |_, this: &Self, _: ()| -> LuaResult<u16> {
			Ok(this.sockport)
		});

		methods.add_method("close", |_, this: &Self, _: ()| -> LuaResult<()> {
			// this can only fail when the socket is already dead
			let _ = this.tx.send(ControlMessage::Close);
			Ok(())
		});
	}
}

impl ListenerHandle {
	fn new_lua<'l>(lua: &'l Lua, sock: TcpListener, listeners: LuaTable, tls_mode: TlsMode) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = sock.local_addr()?;
		let (tx, rx) = mpsc::unbounded_channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{
			tx,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		v.set_user_value(listeners)?;
		let key = lua.create_registry_value(v.clone())?;

		let global_tx = MAIN_CHANNEL.clone_tx();
		ListenerWorker{
			rx,
			global_tx,
			sock,
			tls_mode,
			handle: Arc::new(key),
		}.spawn();
		Ok(v)
	}
}

pub(crate) fn listen<'l>(lua: &'l Lua, (addr, port, listeners, config): (String, u16, LuaTable, Option<LuaTable>)) -> LuaResult<LuaAnyUserData<'l>> {
	let addr = addr.parse::<IpAddr>()?;
	let addr = SocketAddr::new(addr, port);
	let sock = std::net::TcpListener::bind(addr)?;
	sock.set_nonblocking(true)?;

	let tls_mode = match config {
		None => TlsMode::Plain{tls_config: None},
		Some(config) => {
			let tls_config =match config.get::<_, Option<LuaAnyUserData>>("tls_ctx")? {
				Some(v) => match *tls::TlsConfig::get_ref_from_lua(&v)? {
					tls::TlsConfig::Server{ref cfg, ..} => Some(cfg.clone()),
					_ => return Err(LuaError::RuntimeError(format!("attempt to use non-server config with server socket"))),
				},
				None => None,
			};

			match tls_config {
				Some(tls_config) => match config.get::<_, Option<bool>>("tls_direct")?.unwrap_or(false) {
					true => TlsMode::DirectTls{tls_config: tls_config.into()},
					false => TlsMode::Plain{tls_config: Some(tls_config.into())},
				},
				None => TlsMode::Plain{tls_config: None},
			}
		},
	};

	with_runtime_lua! {
		let sock = TcpListener::from_std(sock)?;
		ListenerHandle::new_lua(lua, sock, listeners, tls_mode)
	}
}
