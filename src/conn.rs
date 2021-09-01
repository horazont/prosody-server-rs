/**
# Sockets for stream connections

Sockets for stream connections are generally TCP sockets.
*/
use mlua::prelude::*;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use log::{debug, warn, error};

use bytes::{Bytes, BytesMut, BufMut, buf::Limit};

use tokio::select;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::{TlsAcceptor, server};

use pin_project_lite::pin_project;

use crate::core::{MAIN_CHANNEL, Message, Spawn};
use crate::tls;

/**
Describe which TLS actions are currently possible on a socket.

This enum is used and cached on the lua side to know which operations are possible without having to call into the worker thread for details.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedTlsState {
	/// No context has been set on the socket, so a starttls operation is required to pass a context.
	NoContext,
	/// A context has been set on the socket, so a starttls operation may not pass a socket.
	Possible,
	/// A starttls operation has been initiated; cannot start another one.
	InProgress,
	/// TLS has been established, either via a previous starttls operation or because the socket was accepted with TLS right away.
	Established,
}

enum SocketOption {
	KeepAlive(bool),
}

impl SocketOption {
	fn from_lua_args<'l>(_lua: &'l Lua, option: String, _value: LuaValue) -> Result<SocketOption, String> {
		match option.as_str() {
			"keepalive" => Ok(SocketOption::KeepAlive(true)),
			_ => Err(format!("socket option not supported: {}", option)),
		}
	}
}

enum ControlMessage {
	Close,
	Write(Bytes),
	SetOption(SocketOption),
	StartTls(Option<Arc<tls::TlsConfig>>)
}

pub(crate) struct ConnectionHandle {
	tx: mpsc::UnboundedSender<ControlMessage>,
	tls_state: CachedTlsState,
	sockaddr: String,
	sockport: u16,
}

impl ConnectionHandle {
	fn send_set_option(&self, option: SocketOption) {
		let _ = self.tx.send(ControlMessage::SetOption(option));
	}
}

impl LuaUserData for ConnectionHandle {
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

		methods.add_method("ssl", |_, this: &Self, _: ()| -> LuaResult<bool> {
			Ok(this.tls_state == CachedTlsState::Established)
		});

		methods.add_method("ssl_info", |_, this: &Self, _: ()| -> LuaResult<()> {
			// TODO: return something useful here
			Ok(())
		});

		methods.add_method("setoption", |lua, this: &Self, name: String| -> LuaResult<(bool, Option<String>)> {
			let option = match SocketOption::from_lua_args(lua, name, LuaValue::Nil) {
				Ok(v) => v,
				Err(e) => return Ok((false, Some(e))),
			};
			this.send_set_option(option);
			Ok((true, None))
		});

		methods.add_method_mut("starttls", |lua, this: &mut Self, ctx: Option<tls::TlsConfigHandle>| -> LuaResult<(bool, Option<String>)> {
			Ok(match this.tls_state {
				CachedTlsState::NoContext if ctx.is_none() => {
					(false, Some("server socket has no TLS context associated and no context passed to starttls()".into()))
				},
				CachedTlsState::NoContext | CachedTlsState::Possible => {
					let mut old_tls_state = CachedTlsState::InProgress;
					std::mem::swap(&mut this.tls_state, &mut old_tls_state);
					match this.tx.send(ControlMessage::StartTls(ctx.map(|x| { x.0 }))) {
						Ok(_) => (true, None),
						Err(_) => {
							std::mem::swap(&mut this.tls_state, &mut old_tls_state);
							(false, Some("failed to communicate with socket".into()))
						}
					}
				},
				CachedTlsState::InProgress => {
					(false, Some("TLS operation is in progress".into()))
				},
				CachedTlsState::Established => {
					(false, Some("TLS already established".into()))
				},
			})
		});

		methods.add_method("write", |lua, this: &Self, data: LuaString| -> LuaResult<usize> {
			let data: Bytes = Bytes::copy_from_slice(data.as_bytes());
			let len = data.len();
			match this.tx.send(ControlMessage::Write(data)) {
				Ok(_) => Ok(len),
				Err(_) => Ok(0),
			}
		});

		methods.add_method("close", |_, this: &Self, _: ()| -> LuaResult<()> {
			// this can only fail when the socket is already dead
			let _ = this.tx.send(ControlMessage::Close);
			Ok(())
		});
	}
}

impl ConnectionHandle {
	fn wrap_state<'l>(lua: &'l Lua, conn: ConnectionState, listeners: LuaTable, addr: SocketAddr, tls_state: CachedTlsState) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			tls_state: CachedTlsState::NoContext,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		v.set_user_value(listeners)?;
		let key = lua.create_registry_value(v.clone())?;

		let global_tx = MAIN_CHANNEL.clone_tx();
		ConnectionWorker{
			global_tx,
			rx,
			conn,
			read_size: 8192,
			handle: Arc::new(key),
			buf: None,
		}.spawn();
		Ok(v)
	}

	pub(crate) fn wrap_plain<'l>(lua: &'l Lua, conn: TcpStream, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::PlainServer{sock: conn, tls_config: None}, listeners, addr, CachedTlsState::NoContext)
	}

	pub(crate) fn wrap_tls<'l>(lua: &'l Lua, conn: server::TlsStream<TcpStream>, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.get_ref().0.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::TlsServer{sock: conn}, listeners, addr, CachedTlsState::Established)
	}

	pub(crate) fn confirm_starttls(&mut self) {
		self.tls_state = CachedTlsState::Established;
	}
}

#[derive(Debug)]
struct OpaqueError(String);

impl fmt::Display for OpaqueError {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for OpaqueError {}

pin_project! {
	#[project = ConnectionStateProj]
	enum ConnectionState {
		Broken{e: Option<Box<dyn std::error::Error + Send + 'static>>},
		PlainServer{
			#[pin]
			sock: TcpStream,
			tls_config: Option<TlsAcceptor>,
		},
		TlsServer{
			#[pin]
			sock: server::TlsStream<TcpStream>,
		},
	}
}

impl ConnectionState {
	fn broken_err(e: &Option<Box<dyn std::error::Error + Send + 'static>>) -> io::Error {
		match e {
			Some(e) => io::Error::new(io::ErrorKind::ConnectionReset, format!("connection invalidated because of a previous failed operation: {}", e)),
			None => io::Error::new(io::ErrorKind::ConnectionReset, "connection invalidated because of a previous failed operation (unknown error)"),
		}
	}

	async fn starttls_server(&mut self, sock: TcpStream, acceptor: TlsAcceptor) -> io::Result<()> {
		match acceptor.accept(sock).await {
			Ok(sock) => {
				*self = Self::TlsServer{
					sock,
				};
				Ok(())
			},
			Err(e) => {
				// kaboom, break the thing
				*self = Self::Broken{e: Some(Box::new(
					OpaqueError(format!("failed to accept TLS connection: {}", e))
				))};
				Err(e)
			},
		}
	}

	async fn starttls(&mut self, ctx: Option<Arc<tls::TlsConfig>>) -> io::Result<()> {
		let mut tmp = ConnectionState::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsServer{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::PlainServer{sock, tls_config} => {
				match ctx {
					Some(cfg) => match *cfg {
						tls::TlsConfig::Server{ref cfg, ..} => self.starttls_server(sock, TlsAcceptor::from(cfg.clone())).await,
						tls::TlsConfig::Client(ref cfg) => {
							todo!()
						},
					},
					None => match tls_config {
						Some(acceptor) => self.starttls_server(sock, acceptor).await,
						None => {
							*self = Self::PlainServer{
								sock: sock,
								tls_config: None,
							};
							Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket without TLS context"))
						},
					},
				}
			},
		}
	}
}

impl AsRawFd for ConnectionState {
	fn as_raw_fd(&self) -> RawFd {
		match self {
			ConnectionState::Broken{e} => panic!("attempt to get fd from broken connection ({:?})", e),
			ConnectionState::PlainServer{sock, ..} => sock.as_raw_fd(),
			ConnectionState::TlsServer{sock} => sock.get_ref().0.as_raw_fd(),
		}
	}
}

impl AsyncRead for ConnectionState {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_read(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for ConnectionState {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_write(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write(cx, buf),
		}
	}

	fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_write_vectored(cx, bufs),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write_vectored(cx, bufs),
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_flush(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_flush(cx),
		}
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_shutdown(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_shutdown(cx),
		}
	}

	fn is_write_vectored(&self) -> bool {
		match self {
			Self::Broken{..} => false,
			Self::PlainServer{sock, ..} => sock.is_write_vectored(),
			Self::TlsServer{sock, ..} => sock.is_write_vectored(),
		}
	}
}

enum MsgResult {
	WriteClosed,
	Continue,
	Exit,
}

struct ConnectionWorker {
	global_tx: mpsc::Sender<Message>,
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	conn: ConnectionState,
	read_size: usize,
	buf: Option<Limit<BytesMut>>,
	handle: Arc<LuaRegistryKey>,
}

enum ReadResult {
	Closed,
	Continue,
}

#[inline]
fn mkbuffer(buf: &mut Option<Limit<BytesMut>>, size: usize) -> &mut Limit<BytesMut> {
	buf.get_or_insert_with(|| {
		BytesMut::with_capacity(size).limit(size)
	})
}

#[inline]
async fn read_with_buf(conn: &mut ConnectionState, buf: &mut Option<Limit<BytesMut>>, size: usize) -> io::Result<Option<Bytes>> {
	conn.read_buf(mkbuffer(buf, size)).await?;
	if buf.as_ref().unwrap().get_ref().len() == 0 {
		Ok(None)
	} else {
		Ok(Some(buf.take().unwrap().into_inner().freeze()))
	}
}

impl ConnectionWorker {
	#[inline]
	async fn proc_read_buffer(&mut self, buf: Option<Bytes>) -> Result<ReadResult, ()> {
		if let Some(buf) = buf {
			if buf.len() > 0 {
				let result = match self.global_tx.send(Message::Incoming{
					handle: self.handle.clone(),
					data: buf,
				}).await {
					Ok(_) => Ok(ReadResult::Continue),
					// again, only during shutdown
					Err(_) => Err(()),
				};
				return result
			}
		}

		// end of file
		match self.global_tx.send(Message::ReadClosed{handle: self.handle.clone()}).await {
			Ok(_) => Ok(ReadResult::Closed),
			Err(_) => Err(()),
		}
	}

	#[inline]
	async fn proc_write_buffer(&mut self, buf: Bytes) -> Result<(), ()> {
		// TODO: asynchronize this in some way?
		match self.conn.write_all(&buf).await {
			Ok(_) => Ok(()),
			Err(e) => {
				// TODO: report this to lua, I guess
				error!("write error: {}", e);
				Err(())
			},
		}
	}

	async fn run_draining(mut self) {
		self.buf = None;
		select! {
			_ = self.conn.shutdown() => return,
			_ = self.global_tx.closed() => return,
		}
	}

	async fn run_wclosed(mut self) {
		loop {
			select! {
				result = read_with_buf(&mut self.conn, &mut self.buf, self.read_size) => match result {
					Ok(buf) => match self.proc_read_buffer(buf).await {
						Ok(ReadResult::Closed) => return self.run_draining().await,
						Ok(ReadResult::Continue) => (),
						Err(()) => return,
					},
					Err(e) => {
						warn!("read error: {}", e);
						// TODO: report this to lua, I guess
						return
					},
				},
				_ = self.global_tx.closed() => return,
			}
		}
	}

	fn set_keepalive(&self, enabled: bool) -> Result<(), io::Error> {
		nix::sys::socket::setsockopt(
			self.conn.as_raw_fd(),
			nix::sys::socket::sockopt::KeepAlive,
			&enabled,
		)?;
		Ok(())
	}

	#[inline]
	async fn proc_msg(&mut self, msg: ControlMessage) -> MsgResult {
		match msg {
			ControlMessage::Close => MsgResult::WriteClosed,
			ControlMessage::SetOption(option) => {
				match option {
					SocketOption::KeepAlive(enabled) => {
						match self.set_keepalive(enabled) {
							Ok(_) => (),
							Err(e) => warn!("failed to set keepalive ({}) on socket: {}", enabled, e),
						}
					}
				};
				MsgResult::Continue
			},
			ControlMessage::StartTls(ctx) => {
				match self.conn.starttls(ctx).await {
					Ok(_) => {
						match self.global_tx.send(Message::TlsStarted{handle: self.handle.clone()}).await {
							Ok(_) => MsgResult::Continue,
							Err(_) => MsgResult::Exit,
						}
					},
					Err(e) => {
						debug!("TLS handshake error: {}", e);
						// gotta leave here.
						let _ = self.global_tx.send(Message::Disconnect{handle: self.handle.clone(), error: Some(Box::new(e))}).await;
						MsgResult::Exit
					},
				}
			},
			ControlMessage::Write(buf) => match self.proc_write_buffer(buf).await {
				Ok(()) => MsgResult::Continue,
				Err(()) => MsgResult::Exit,
			},
		}
	}

	async fn run_rclosed(mut self) {
		self.buf = None;
		loop {
			select! {
				msg = self.rx.recv() => match msg {
					Some(msg) => match self.proc_msg(msg).await {
						MsgResult::Exit => return,
						MsgResult::Continue => (),
						MsgResult::WriteClosed => return self.run_draining().await,
					},
					None => return,
				},
				_ = self.global_tx.closed() => return,
			}
		}
	}

	async fn run(mut self) {
		loop {
			select! {
				msg = self.rx.recv() => match msg {
					Some(msg) => match self.proc_msg(msg).await {
						MsgResult::Exit => return,
						MsgResult::Continue => (),
						MsgResult::WriteClosed => return self.run_wclosed().await,
					},
					None => return,
				},
				result = read_with_buf(&mut self.conn, &mut self.buf, self.read_size) => match result {
					Ok(buf) => match self.proc_read_buffer(buf).await {
						Ok(ReadResult::Closed) => return self.run_rclosed().await,
						Ok(ReadResult::Continue) => (),
						Err(()) => return,
					},
					Err(e) => {
						warn!("read error: {}", e);
						// TODO: report this to lua, I guess
						return
					},
				},
				_ = self.global_tx.closed() => return,
			}
		}
	}
}

impl Spawn for ConnectionWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}
