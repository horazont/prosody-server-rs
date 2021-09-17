/**
# Listener sockets for stream connections

Listener sockets for stream connections are generally TCP sockets. They may additionally have a TLS context associated to also transition to TLS right away or to forward the context to connections for later use with STARTTLS.
*/
use mlua::prelude::*;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::select;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::TlsAcceptor;

use crate::{with_runtime_lua, strerror_ok, send_log};
use crate::core::{MAIN_CHANNEL, Message, Spawn, LuaRegistryHandle};
use crate::conversion;
use crate::conversion::opaque;
use crate::tls;
use crate::config;
use crate::config::CONFIG;
use crate::ioutil::iotimeout;
use crate::verify;


type ServerTlsCfg = (TlsAcceptor, Arc<verify::RecordingClientVerifier>);

/**
Control if and how TLS is accepted on listener sockets.
*/
#[derive(Clone)]
enum TlsMode {
	/// TLS is never established, but if the `tls_config` is given, it will be forwarded to any created connections for later use with STARTTLS.
	Plain{
		tls_config: Option<ServerTlsCfg>,
	},
	/// TLS will always attempted and if it fails, the Lua side will never see the connection.
	DirectTls{
		tls_config: ServerTlsCfg,
	},
	/// TLS is established if the first byte on the connection is 0x16 (the TLS handshake start). Otherwise, the connection is handled as plaintext connection.
	///
	/// In case of a plaintext connection, the TLS config is forwarded to the connection socket for later use with STARTTLS.
	Multiplex{
		tls_config: ServerTlsCfg,
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
	async fn accept(&self, handle: &'_ LuaRegistryHandle, conn: TcpStream, addr: SocketAddr, ssl_handshake_timeout: Duration) -> io::Result<Message> {
		match self {
			Self::Plain{..} => {
				Ok(Message::TcpAccept{
					handle: handle.clone(),
					stream: conn,
					addr,
				})
			},
			Self::DirectTls{tls_config: (acceptor, recorder)} => {
				let (verify, conn) = recorder.scope(async move {
					iotimeout(ssl_handshake_timeout, acceptor.accept(conn), "TLS handshake timed out").await
				}).await;
				Ok(Message::TlsAccept{
					handle: handle.clone(),
					stream: conn?,
					addr,
					verify,
				})
			},
			Self::Multiplex{tls_config: (acceptor, recorder)} => {
				let mut buf = [0u8; 1];
				match conn.peek(&mut buf).await? {
					// first byte of the TLS handshake
					1 if buf[0] == 0x16 => {
						let (verify, conn) = recorder.scope(async move {
							iotimeout(ssl_handshake_timeout, acceptor.accept(conn), "TLS handshake timed out").await
						}).await;
						Ok(Message::TlsAccept{
							handle: handle.clone(),
							stream: conn?,
							addr,
							verify,
						})
					},
					// if no byte is read or if it doesn't match -> assume plaintext
					_ => {
						Ok(Message::TcpAccept{
							handle: handle.clone(),
							stream: conn,
							addr,
						})
					},
				}
			},
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
	tls_mode: TlsMode,
	cfg: config::ServerConfig,
	stream_cfg: config::StreamConfig,
	sock: TcpListener,
	handle: LuaRegistryHandle,
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
						let msg = match self.tls_mode.accept(&self.handle, conn, addr, self.stream_cfg.ssl_handshake_timeout).await {
							Ok(msg) => msg,
							Err(e) => {
								send_log!("debug", "failed to handshake with peer", Some(e));
								continue;
							},
						};
						// we don't care about failure here; this can only fail during shutdown when nobody else cares anymore either.
						MAIN_CHANNEL.fire_and_forget(msg).await;
					},
					Err(e) => {
						send_log!("error", "failed to accept socket from listener! backing off!", Some(e));
						tokio::time::sleep(self.cfg.accept_retry_interval).await;
					},
				},
				// when the global tx queue is gone, we don't need to accept anything anymore and can just go to rest
				_ = MAIN_CHANNEL.closed() => return,
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
	tls_config: Option<Arc<tls::TlsConfig>>,
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

		methods.add_method("sslctx", |_, this: &Self, _: ()| -> LuaResult<Option<tls::TlsConfigHandle>> {
			Ok(this.tls_config.as_ref().map(|x| { tls::TlsConfigHandle(x.clone()) }))
		});

		methods.add_method("close", |_, this: &Self, _: ()| -> LuaResult<()> {
			// this can only fail when the socket is already dead
			let _ = this.tx.send(ControlMessage::Close);
			Ok(())
		});
	}
}

impl ListenerHandle {
	fn new_lua<'l>(
			lua: &'l Lua,
			sock: TcpListener,
			listeners: LuaTable,
			tls_config: Option<Arc<tls::TlsConfig>>,
			tls_mode: TlsMode,
			server_cfg: config::ServerConfig,
			stream_cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = sock.local_addr()?;
		let (tx, rx) = mpsc::unbounded_channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{
			tx,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
			tls_config,
		})?;
		v.set_user_value(listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		ListenerWorker{
			rx,
			sock,
			tls_mode,
			handle,
			cfg: server_cfg,
			stream_cfg,
		}.spawn();
		Ok(v)
	}
}

fn mk_listen_socket(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
	let domain = socket2::Domain::for_address(addr);
	let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
	if domain == socket2::Domain::IPV6 {
		// if it doesn't work, it doesn't work
		let _ = sock.set_only_v6(true);
	}
	sock.set_nonblocking(true)?;
	sock.set_reuse_address(true)?;
	sock.bind(&addr.into())?;
	sock.listen(0)?;
	Ok(sock.into())
}

pub(crate) fn listen<'l>(lua: &'l Lua, (addr, port, listeners, config): (LuaValue, u16, LuaTable, Option<LuaTable>)) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let addr = strerror_ok!(conversion::to_ipaddr(&addr));
	let addr = SocketAddr::new(addr, port);
	let sock = match mk_listen_socket(addr) {
		Ok(v) => v,
		Err(e) => return Ok(Err(format!("failed to bind to {}: {}", addr, e))),
	};

	let (tls_config, tls_mode) = match config {
		None => (None, TlsMode::Plain{tls_config: None}),
		Some(config) => {
			let outer_tls_config = match config.get::<_, Option<LuaAnyUserData>>("tls_ctx")? {
				Some(v) => Some((*tls::TlsConfigHandle::get_ref_from_lua(&v)?).clone()),
				None => None,
			};

			let tls_config = match outer_tls_config.as_ref().map(|x| { x.as_ref() }) {
				Some(tls::TlsConfig::Server{ref cfg, ref recorder, ..}) => Some((cfg.clone(), recorder.clone())),
				Some(_) => return Err(opaque("attempt to use non-server config with server socket").into()),
				None => None,
			};

			(outer_tls_config.map(|x| { x.0 }), match tls_config {
				Some((tls_config, recorder)) => match config.get::<_, Option<bool>>("tls_direct")?.unwrap_or(false) {
					true => match config.get::<_, Option<bool>>("tls_auto")?.unwrap_or(false) {
						true => TlsMode::Multiplex{tls_config: (tls_config.into(), recorder)},
						false => TlsMode::DirectTls{tls_config: (tls_config.into(), recorder)},
					},
					false => TlsMode::Plain{tls_config: Some((tls_config.into(), recorder))},
				},
				None => TlsMode::Plain{tls_config: None},
			})
		},
	};

	let (server_cfg, stream_cfg) = {
		let config = CONFIG.read().unwrap();
		(config.server, config.stream)
	};

	with_runtime_lua! {
		let sock = TcpListener::from_std(sock)?;
		Ok(Ok(ListenerHandle::new_lua(lua, sock, listeners, tls_config, tls_mode, server_cfg, stream_cfg)?))
	}
}
