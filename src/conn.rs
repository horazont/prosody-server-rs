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

use tokio_rustls::{TlsAcceptor, TlsConnector, server, client};

use pin_project_lite::pin_project;

use crate::{with_runtime_lua, strerror_ok};
use crate::core::{MAIN_CHANNEL, Message, Spawn, LuaRegistryHandle};
use crate::tls;
use crate::conversion;

/**
Describe which TLS actions are currently possible on a socket.

This enum is used and cached on the lua side to know which operations are possible without having to call into the worker thread for details.
*/
#[derive(Clone)]
enum CachedTlsState {
	/// No context has been set on the socket, so a starttls operation is required to pass a context.
	NoConfig,
	MayAccept(Arc<rustls::ServerConfig>),
	MayConnect(webpki::DNSName, Arc<rustls::ClientConfig>),
	/* AcceptInProgress(Arc<rustls::ServerConfig>),
	ConnectInProgress(webpki::DNSName, Arc<rustls::ClientConfig>), */
	InProgress,
	Established,
}

impl CachedTlsState {
	fn transition(&mut self, given_config: Option<&tls::TlsConfig>) -> Result<ControlMessage, String> {
		match self {
			Self::InProgress => Err("TLS operation already in progress".into()),
			Self::Established => Err("TLS already established".into()),
			Self::NoConfig => match given_config {
				// We can only *accept* connections based on the given config, as we lack a target hostname
				Some(tls::TlsConfig::Client{..}) => Err("cannoct initiate TLS connection without target server name (i.e. on a server socket)".into()),
				Some(tls::TlsConfig::Server{cfg, ..}) => {
					*self = Self::InProgress;
					Ok(ControlMessage::AcceptTls(cfg.clone()))
				},
				None => Err("cannot start TLS connection without context".into()),
			},
			Self::MayAccept(cfg) => match given_config {
				// We can only *accept* connections based on the given config, as we lack a target hostname
				Some(tls::TlsConfig::Client{..}) => Err("cannoct initiate TLS connection without target server name (i.e. on a server socket)".into()),
				Some(tls::TlsConfig::Server{cfg, ..}) => {
					let msg = ControlMessage::AcceptTls(cfg.clone());
					*self = Self::InProgress;
					Ok(msg)
				},
				None => {
					let msg = ControlMessage::AcceptTls(cfg.clone());
					*self = Self::InProgress;
					Ok(msg)
				},
			},
			Self::MayConnect(name, cfg) => match given_config {
				// We can only *accept* connections based on the given config, as we lack a target hostname
				Some(tls::TlsConfig::Client{cfg}) => {
					let msg = ControlMessage::ConnectTls(name.clone(), cfg.clone());
					*self = Self::InProgress;
					Ok(msg)
				},
				Some(tls::TlsConfig::Server{cfg, ..}) => {
					let msg = ControlMessage::AcceptTls(cfg.clone());
					*self = Self::InProgress;
					Ok(msg)
				},
				None => {
					let msg = ControlMessage::ConnectTls(name.clone(), cfg.clone());
					*self = Self::InProgress;
					Ok(msg)
				},
			},
		}
	}
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
	AcceptTls(Arc<rustls::ServerConfig>),
	ConnectTls(webpki::DNSName, Arc<rustls::ClientConfig>),
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
			Ok(match this.tls_state {
				CachedTlsState::Established => true,
				_ => false,
			})
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
			let ctx_arc = ctx.map(|x| { x.0 });
			let ctx_ref = ctx_arc.as_ref().map(|x| { &**x });
			match this.tls_state.transition(ctx_ref) {
				Ok(_) => Ok((true, None)),
				Err(e) => Ok((false, Some(e))),
			}
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
			tls_state,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		v.set_user_value(listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		let global_tx = MAIN_CHANNEL.clone_tx();
		ConnectionWorker{
			global_tx,
			rx,
			conn,
			read_size: 8192,
			handle,
			buf: None,
		}.spawn();
		Ok(v)
	}

	fn connect<'l>(lua: &'l Lua, addr: SocketAddr, listeners: LuaTable, tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>)>) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			// we might establish TLS right away, in that case it doesn't matter
			tls_state: CachedTlsState::NoConfig,
			// this is actually correct because ip() is supposed to return the remote IP for clients
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		v.set_user_value(listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		let global_tx = MAIN_CHANNEL.clone_tx();
		ConnectWorker{
			global_tx,
			rx,
			addr,
			tls_config,
			read_size: 8192,
			handle,
		}.spawn();
		Ok(v)
	}

	pub(crate) fn wrap_plain<'l>(lua: &'l Lua, conn: TcpStream, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::Plain{sock: conn}, listeners, addr, CachedTlsState::NoConfig)
	}

	pub(crate) fn wrap_tls_server<'l>(lua: &'l Lua, conn: server::TlsStream<TcpStream>, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
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
		Plain{
			#[pin]
			sock: TcpStream,
		},
		TlsServer{
			#[pin]
			sock: server::TlsStream<TcpStream>,
		},
		TlsClient{
			#[pin]
			sock: client::TlsStream<TcpStream>,
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

	async fn starttls_client(&mut self, sock: TcpStream, name: webpki::DNSNameRef<'_>, connector: TlsConnector) -> io::Result<()> {
		match connector.connect(name, sock).await {
			Ok(sock) => {
				*self = Self::TlsClient{
					sock,
				};
				Ok(())
			},
			Err(e) => {
				// kaboom, break the thing
				*self = Self::Broken{e: Some(Box::new(
					OpaqueError(format!("failed to initiate TLS connection: {}", e))
				))};
				Err(e)
			},
		}
	}

	async fn starttls_connect(&mut self, name: webpki::DNSNameRef<'_>, ctx: Arc<rustls::ClientConfig>) -> io::Result<()> {
		let mut tmp = ConnectionState::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsServer{..} | Self::TlsClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::Plain{sock} => self.starttls_client(sock, name, ctx.into()).await,
		}
	}

	async fn starttls_accept(&mut self, ctx: Arc<rustls::ServerConfig>) -> io::Result<()> {
		let mut tmp = ConnectionState::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsServer{..} | Self::TlsClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::Plain{sock} => self.starttls_server(sock, ctx.into()).await,
		}
	}
}

impl AsRawFd for ConnectionState {
	fn as_raw_fd(&self) -> RawFd {
		match self {
			Self::Broken{e} => panic!("attempt to get fd from broken connection ({:?})", e),
			Self::Plain{sock, ..} => sock.as_raw_fd(),
			Self::TlsServer{sock} => sock.get_ref().0.as_raw_fd(),
			Self::TlsClient{sock} => sock.get_ref().0.as_raw_fd(),
		}
	}
}

impl AsyncRead for ConnectionState {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::Plain{sock, ..} => sock.poll_read(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_read(cx, buf),
			ConnectionStateProj::TlsClient{sock} => sock.poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for ConnectionState {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::Plain{sock, ..} => sock.poll_write(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write(cx, buf),
			ConnectionStateProj::TlsClient{sock} => sock.poll_write(cx, buf),
		}
	}

	fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::Plain{sock, ..} => sock.poll_write_vectored(cx, bufs),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write_vectored(cx, bufs),
			ConnectionStateProj::TlsClient{sock} => sock.poll_write_vectored(cx, bufs),
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::Plain{sock, ..} => sock.poll_flush(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_flush(cx),
			ConnectionStateProj::TlsClient{sock} => sock.poll_flush(cx),
		}
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
			ConnectionStateProj::Plain{sock, ..} => sock.poll_shutdown(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_shutdown(cx),
			ConnectionStateProj::TlsClient{sock} => sock.poll_shutdown(cx),
		}
	}

	fn is_write_vectored(&self) -> bool {
		match self {
			Self::Broken{..} => false,
			Self::Plain{sock, ..} => sock.is_write_vectored(),
			Self::TlsServer{sock, ..} => sock.is_write_vectored(),
			Self::TlsClient{sock, ..} => sock.is_write_vectored(),
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
	handle: LuaRegistryHandle,
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
			ControlMessage::AcceptTls(ctx) => {
				match self.conn.starttls_accept(ctx).await {
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
			ControlMessage::ConnectTls(name, ctx) => {
				match self.conn.starttls_connect(name.as_ref(), ctx).await {
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

struct ConnectWorker {
	global_tx: mpsc::Sender<Message>,
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	addr: SocketAddr,
	read_size: usize,
	tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>)>,
	handle: LuaRegistryHandle,
}

impl ConnectWorker {
	async fn run(mut self) {
		let sock = match TcpStream::connect(self.addr).await {
			Ok(sock) => sock,
			Err(e) => {
				let _ = self.global_tx.send(Message::Disconnect{
					handle: self.handle,
					error: Some(Box::new(e)),
				}).await;
				return;
			},
		};
		let conn = match self.tls_config {
			Some((name, config)) => {
				let connector: TlsConnector = config.into();
				let sock = match connector.connect(name.as_ref(), sock).await {
					Ok(sock) => sock,
					Err(e) => {
						let _ = self.global_tx.send(Message::Disconnect{
							handle: self.handle,
							error: Some(Box::new(e)),
						}).await;
						return;
					},
				};
				ConnectionState::TlsClient{sock}
			},
			None => ConnectionState::Plain{sock},
		};
		match self.global_tx.send(Message::Connect{handle: self.handle.clone()}).await {
			Ok(_) => (),
			// can only happen during shutdown, drop it.
			Err(_) => return,
		};
		return ConnectionWorker{
			global_tx: self.global_tx,
			rx: self.rx,
			read_size: self.read_size,
			conn,
			buf: None,
			handle: self.handle,
		}.run().await;
	}
}

impl Spawn for ConnectWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}

pub(crate) fn addclient<'l>(
		lua: &'l Lua,
		(addr, port, listeners, read_size, tls_ctx, typ, extra): (LuaValue, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaString>, Option<LuaTable>)
		) -> LuaResult<Result<LuaAnyUserData<'l>, String>>
{
	let addr = strerror_ok!(conversion::to_ipaddr(&addr));
	let addr = SocketAddr::new(addr, port);

	let tls_ctx = match tls_ctx {
		None => None,
		Some(tls_ctx) => match &*tls_ctx.0 {
			tls::TlsConfig::Client{cfg} => Some(cfg.clone()),
			_ => return Ok(Err(format!("non-client TLS config passed to client socket"))),
		}
	};

	// extra is required, we MUST have the server name...
	let tls_config = match (tls_ctx, extra.as_ref()) {
		(Some(tls_ctx), Some(extra)) => {
			let servername = match extra.get::<_, Option<LuaString>>("servername") {
				Ok(Some(v)) => v,
				Ok(None) => return Ok(Err(format!("missing option servername (required for TLS, and TLS context is given)"))),
				Err(e) => return Ok(Err(format!("invalid option servername (required for TLS, and TLS context is given): {}", e))),
			};
			let servername = match webpki::DNSNameRef::try_from_ascii(servername.as_bytes()) {
				Ok(v) => v,
				Err(e) => return Ok(Err(format!("servername is not a DNSName: {}", e))),
			};
			Some((servername.to_owned(), tls_ctx))
		},
		(Some(tls_ctx), None) => {
			return Ok(Err(format!("cannot connect via TLS without a servername")))
		},
		(None, None) | (None, Some(_)) => None,
	};

	with_runtime_lua!{
		Ok(Ok(ConnectionHandle::connect(lua, addr, listeners, tls_config)?))
	}
}
