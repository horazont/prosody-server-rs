/**
# Sockets for stream connections

Sockets for stream connections are generally TCP sockets.
*/
use mlua::prelude::*;

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut, BufMut, buf::Limit};

use tokio::select;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::{TlsAcceptor, TlsConnector, server, client};

use pin_project_lite::pin_project;

use nix::{
	fcntl::FcntlArg,
	fcntl::fcntl,
};

use crate::{with_runtime_lua, strerror_ok};
use crate::core::{MAIN_CHANNEL, Message, Spawn, LuaRegistryHandle};
use crate::tls;
use crate::conversion;
use crate::verify;
use crate::cert;

/**
Describe which TLS actions are currently possible on a socket.

This enum is used and cached on the lua side to know which operations are possible without having to call into the worker thread for details.
*/
#[derive(Clone)]
enum CachedTlsState {
	/// No context has been set on the socket, so a starttls operation is required to pass a context.
	NoConfig,
	// these are currently never constructed because we don't pass TLS config info from the listener to the conn. could be done trivially if needed.
	#[allow(dead_code)]
	MayAccept(Arc<rustls::ServerConfig>),
	#[allow(dead_code)]
	MayConnect(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>),
	/* AcceptInProgress(Arc<rustls::ServerConfig>),
	ConnectInProgress(webpki::DNSName, Arc<rustls::ClientConfig>), */
	InProgress,
	Established{
		verify: verify::VerificationRecord,
	},
}

impl CachedTlsState {
	fn transition(&mut self, given_config: Option<&tls::TlsConfig>, given_servername: Option<webpki::DNSNameRef>) -> Result<ControlMessage, String> {
		match self {
			Self::InProgress => Err("TLS operation already in progress".into()),
			Self::Established{..} => Err("TLS already established".into()),
			Self::NoConfig => match given_config {
				// We can only *accept* connections based on the given config, as we lack a target hostname
				Some(tls::TlsConfig::Client{cfg, recorder}) => match given_servername {
					Some(v) => {
						*self = Self::InProgress;
						Ok(ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone()))
					},
					None => Err("cannoct initiate TLS connection without target server name (i.e. on a server socket)".into()),
				},
				Some(tls::TlsConfig::Server{cfg, ..}) => {
					*self = Self::InProgress;
					Ok(ControlMessage::AcceptTls(cfg.clone()))
				},
				None => Err("cannot start TLS connection without context".into()),
			},
			Self::MayAccept(cfg) => match given_config {
				// We can only *accept* connections based on the given config, as we lack a target hostname
				Some(tls::TlsConfig::Client{cfg, recorder}) => match given_servername {
					Some(v) => {
						*self = Self::InProgress;
						Ok(ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone()))
					},
					None => Err("cannoct initiate TLS connection without target server name (i.e. on a server socket)".into()),
				},
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
			Self::MayConnect(name, cfg, recorder) => {
				let name = match given_servername {
					Some(name) => name.to_owned(),
					None => name.clone(),
				};
				match given_config {
					// We can only *accept* connections based on the given config, as we lack a target hostname
					Some(tls::TlsConfig::Client{cfg, recorder}) => {
						let msg = ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone());
						*self = Self::InProgress;
						Ok(msg)
					},
					Some(tls::TlsConfig::Server{cfg, ..}) => {
						let msg = ControlMessage::AcceptTls(cfg.clone());
						*self = Self::InProgress;
						Ok(msg)
					},
					None => {
						let msg = ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone());
						*self = Self::InProgress;
						Ok(msg)
					},
				}
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
	BlockReads,
	BlockWrites,
	UnblockWrites,
	Write(Bytes),
	SetOption(SocketOption),
	AcceptTls(Arc<rustls::ServerConfig>),
	ConnectTls(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>),
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
				CachedTlsState::Established{..} => true,
				_ => false,
			})
		});

		methods.add_method("ssl_info", |_, _this: &Self, _: ()| -> LuaResult<()> {
			// TODO: return something useful here
			Ok(())
		});

		methods.add_method("ssl_peercertificate", |_, this, _: ()| -> LuaResult<Option<cert::ParsedCertificate>> {
			match &this.tls_state {
				CachedTlsState::Established{verify, ..} => match verify {
					verify::VerificationRecord::Unverified | verify::VerificationRecord::Failed{..} => {
						Ok(None)
					},
					verify::VerificationRecord::Passed{cert: certificate} => {
						Ok(cert::ParsedCertificate::from_der(Cow::Borrowed(&certificate.0)).ok())
					},
				},
				_ => Ok(None)
			}
		});

		methods.add_method("ssl_peerverification", |lua, this: &Self, _: ()| -> LuaResult<(bool, LuaTable)> {
			let reasons = lua.create_table()?;
			match &this.tls_state {
				CachedTlsState::Established{verify, ..} => match verify {
					verify::VerificationRecord::Unverified => {
						reasons.raw_set(1, "verification disabled or did not complete")?;
						Ok((false, reasons))
					},
					verify::VerificationRecord::Passed{..} => {
						Ok((true, reasons))
					},
					verify::VerificationRecord::Failed{err} => {
						reasons.raw_set(1, format!("{}", err))?;
						Ok((true, reasons))
					},
				},
				_ => Ok((false, reasons))
			}
		});

		methods.add_method("block_reads", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::BlockReads);
			Ok(())
		});

		methods.add_method("pause_writes", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::BlockWrites);
			Ok(())
		});

		methods.add_method("resume_writes", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::UnblockWrites);
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

		methods.add_method_mut("starttls", |_, this: &mut Self, (ctx, servername): (Option<tls::TlsConfigHandle>, Option<LuaString>)| -> LuaResult<()> {
			let ctx_arc = ctx.map(|x| { x.0 });
			let ctx_ref = ctx_arc.as_ref().map(|x| { &**x });
			let servername_ref = match servername.as_ref().map(|x| { webpki::DNSNameRef::try_from_ascii(x.as_bytes()) }) {
				Some(Ok(v)) => Some(v),
				Some(Err(e)) => return Err(LuaError::RuntimeError(format!("passed server name {:?} is invalid: {}", servername.unwrap().to_string_lossy(), e))),
				None => None,
			};
			match this.tls_state.transition(ctx_ref, servername_ref) {
				Ok(msg) => {
					match this.tx.send(msg) {
						Ok(()) => Ok(()),
						Err(_) => return Err(LuaError::RuntimeError("channel gone!".to_string())),
					}
				},
				Err(e) => return Err(LuaError::RuntimeError(format!("{}", e))),
			}
		});

		methods.add_method("write", |_, this: &Self, data: LuaString| -> LuaResult<usize> {
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

		methods.add_function("setlistener", |_, (this, listeners, data): (LuaAnyUserData, LuaTable, LuaValue)| -> LuaResult<()> {
			let old_listeners = this.get_user_value::<LuaTable>()?;
			match old_listeners.get::<_, Option<LuaFunction>>("ondetach")? {
				Some(func) => func.call::<_, ()>(this.clone())?,
				None => (),
			};
			set_listeners(&this, listeners.clone())?;
			match listeners.get::<_, Option<LuaFunction>>("onattach")? {
				Some(func) => func.call::<_, ()>((this.clone(), data))?,
				None => (),
			};
			Ok(())
		});

		methods.add_meta_function(LuaMetaMethod::Index, |_, (this, key): (LuaAnyUserData, LuaString)| -> LuaResult<LuaValue> {
			let data = this.get_user_value::<LuaTable>()?;
			data.raw_get::<_, LuaValue>(key)
		});

		methods.add_meta_function(LuaMetaMethod::NewIndex, |_, (this, key, value): (LuaAnyUserData, LuaString, LuaValue)| -> LuaResult<()> {
			let data = this.get_user_value::<LuaTable>()?;
			data.raw_set(key, value)
		});
	}
}

impl ConnectionHandle {
	fn wrap_state<'l>(lua: &'l Lua, conn: ConnectionState, listeners: LuaTable, addr: (String, u16), tls_state: CachedTlsState) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			tls_state,
			sockaddr: addr.0,
			sockport: addr.1,
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		let global_tx = MAIN_CHANNEL.clone_tx();
		ConnectionWorker{
			global_tx,
			rx,
			conn,
			read_size: 8192,
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
			tx_buf: None,
			handle,
			buf: None,
		}.spawn();
		Ok(v)
	}

	fn connect<'l>(lua: &'l Lua, addr: SocketAddr, listeners: LuaTable, read_size: usize, tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>)>) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			// we might establish TLS right away, in that case it doesn't matter
			tls_state: CachedTlsState::NoConfig,
			// this is actually correct because ip() is supposed to return the remote IP for clients
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		let global_tx = MAIN_CHANNEL.clone_tx();
		ConnectWorker{
			global_tx,
			rx,
			addr,
			tls_config,
			read_size,
			handle,
		}.spawn();
		Ok(v)
	}

	pub(crate) fn wrap_plain<'l>(lua: &'l Lua, conn: TcpStream, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::Plain{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), CachedTlsState::NoConfig)
	}

	pub(crate) fn wrap_tls_server<'l>(lua: &'l Lua, conn: server::TlsStream<TcpStream>, listeners: LuaTable, addr: Option<SocketAddr>, verify: verify::VerificationRecord) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.get_ref().0.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::TlsServer{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), CachedTlsState::Established{verify})
	}

	pub(crate) fn confirm_starttls(&mut self, verify: verify::VerificationRecord) {
		self.tls_state = CachedTlsState::Established{verify};
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

impl fmt::Debug for ConnectionState {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Broken{e} => f.debug_struct("ConnectionState::Broken").field("e", &e).finish(),
			Self::Plain{..} => f.debug_struct("ConnectionState::Plain").finish_non_exhaustive(),
			Self::TlsServer{..} => f.debug_struct("ConnectionState::TlsServer").finish_non_exhaustive(),
			Self::TlsClient{..} => f.debug_struct("ConnectionState::TlsClient").finish_non_exhaustive(),
		}
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

	async fn starttls_client(&mut self, sock: TcpStream, name: webpki::DNSNameRef<'_>, connector: TlsConnector, recorder: &verify::RecordingVerifier) -> io::Result<verify::VerificationRecord> {
		let (verify, sock) = recorder.scope(async move {
			connector.connect(name, sock).await
		}).await;
		match sock {
			Ok(sock) => {
				*self = Self::TlsClient{
					sock,
				};
				Ok(verify)
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

	async fn starttls_connect(&mut self, name: webpki::DNSNameRef<'_>, ctx: Arc<rustls::ClientConfig>, recorder: &verify::RecordingVerifier) -> io::Result<verify::VerificationRecord> {
		let mut tmp = ConnectionState::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsServer{..} | Self::TlsClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::Plain{sock} => {
				self.starttls_client(sock, name, ctx.into(), recorder).await
			},
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
	Continue,
	Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionMode {
	Closed,
	Blocked,
	Open,
}

impl DirectionMode {
	fn may(&self) -> bool {
		match self {
			Self::Closed | Self::Blocked => false,
			Self::Open => true,
		}
	}

	fn may_ever(&self) -> bool {
		match self {
			Self::Closed => false,
			Self::Open | Self::Blocked  => true,
		}
	}

	fn unblock(&self) -> DirectionMode {
		match self {
			Self::Blocked => Self::Open,
			Self::Open | Self::Closed => *self,
		}
	}

	fn block(&self) -> DirectionMode {
		match self {
			Self::Open => Self::Blocked,
			Self::Blocked | Self::Closed => *self,
		}
	}
}

struct ConnectionWorker {
	global_tx: mpsc::Sender<Message>,
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	conn: ConnectionState,
	read_size: usize,
	buf: Option<Limit<BytesMut>>,
	rx_mode: DirectionMode,
	tx_mode: DirectionMode,
	tx_buf: Option<BytesMut>,
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
	async fn proc_write_buffer(&mut self, buf: Bytes) -> io::Result<()> {
		// TODO: asynchronize this in some way?
		self.conn.write_all(&buf).await
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
	async fn proc_msg(&mut self, msg: ControlMessage) -> io::Result<MsgResult> {
		match msg {
			ControlMessage::Close => {
				// TODO: send a disconnect event
				self.conn.shutdown().await?;
				let _ = self.global_tx.send(Message::Disconnect{handle: self.handle.clone(), error: None}).await;
				Ok(MsgResult::Exit)
			},
			ControlMessage::SetOption(option) => {
				match option {
					SocketOption::KeepAlive(enabled) => self.set_keepalive(enabled)?,
				};
				Ok(MsgResult::Continue)
			},
			ControlMessage::AcceptTls(ctx) => {
				self.conn.starttls_accept(ctx).await?;
				match self.global_tx.send(Message::TlsStarted{handle: self.handle.clone(), verify: verify::VerificationRecord::Unverified}).await {
					Ok(_) => {
						self.rx_mode = self.rx_mode.unblock();
						self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::ConnectTls(name, ctx, recorder) => {
				let verify = self.conn.starttls_connect(name.as_ref(), ctx, &*recorder).await?;
				match self.global_tx.send(Message::TlsStarted{handle: self.handle.clone(), verify}).await {
					Ok(_) => {
						self.rx_mode = self.rx_mode.unblock();
						self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::Write(buf) => if self.tx_mode.may() {
				self.proc_write_buffer(buf).await?;
				Ok(MsgResult::Continue)
			} else if self.tx_mode.may_ever() {
				let tx_buf = self.tx_buf.get_or_insert_with(|| { BytesMut::new() });
				tx_buf.extend_from_slice(&buf);
				Ok(MsgResult::Continue)
			} else {
				// should this instead be a write error or something?!
				Ok(MsgResult::Continue)
			},
			ControlMessage::BlockReads => {
				self.rx_mode = self.rx_mode.block();
				Ok(MsgResult::Continue)
			}
			ControlMessage::BlockWrites => {
				self.tx_mode = self.tx_mode.block();
				Ok(MsgResult::Continue)
			},
			ControlMessage::UnblockWrites => {
				self.tx_mode = self.tx_mode.unblock();
				if self.tx_mode.may() {
					if let Some(buf) = self.tx_buf.take() {
						self.proc_write_buffer(buf.freeze()).await?;
					}
				}
				Ok(MsgResult::Continue)
			},
		}
	}

	async fn run(mut self) {
		loop {
			if !self.rx_mode.may_ever() && !self.tx_mode.may_ever() {
				// if the connection can neither read nor write ever again, we only shutdown and then bail out
				self.buf = None;
				select! {
					_ = self.conn.shutdown() => return,
					_ = self.global_tx.closed() => return,
				}
			}

			select! {
				result = read_with_buf(&mut self.conn, &mut self.buf, self.read_size), if self.rx_mode.may() => match result {
					Ok(buf) => match self.proc_read_buffer(buf).await {
						Ok(ReadResult::Closed) => {
							self.rx_mode = DirectionMode::Closed;
						},
						Ok(ReadResult::Continue) => (),
						Err(()) => return,
					},
					Err(e) => {
						let _ = self.global_tx.send(Message::Disconnect{handle: self.handle, error: Some(Box::new(e))}).await;
						return
					},
				},
				msg = self.rx.recv() => match msg {
					Some(msg) => match self.proc_msg(msg).await {
						Ok(MsgResult::Exit) => return,
						Ok(MsgResult::Continue) => (),
						Err(e) => {
							let _ = self.global_tx.send(Message::Disconnect{handle: self.handle, error: Some(Box::new(e))}).await;
							return
						},
					},
					None => return,
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

pub(crate) fn set_listeners<'l>(ud: &LuaAnyUserData<'l>, listeners: LuaTable<'l>) -> LuaResult<()> {
	let tbl = ud.get_user_value::<LuaTable>()?;
	tbl.set(0, listeners)
}

pub(crate) fn get_listeners<'l>(ud: &LuaAnyUserData<'l>) -> LuaResult<LuaTable<'l>> {
	let tbl = ud.get_user_value::<LuaTable>()?;
	tbl.get::<_, LuaTable>(0)
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
	async fn run(self) {
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
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
			tx_buf: None,
			handle: self.handle,
		}.run().await;
	}
}

impl Spawn for ConnectWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}

pub(crate) fn wrapclient<'l>(
		lua: &'l Lua,
		(fd, addr, port, listeners, _read_size, tls_ctx, extra): (RawFd, String, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaTable>)
		) -> LuaResult<Result<LuaAnyUserData<'l>, String>>
{
	let fd = strerror_ok!(fcntl(
		fd,
		FcntlArg::F_DUPFD_CLOEXEC(0),
	));
	// this is probably the worst one could do... let's hope the syscalls will quickly let this fail
	let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
	strerror_ok!(sock.set_nonblocking(true));
	let sock: std::net::TcpStream = sock.into();

	// extra is required, we MUST have the server name...
	let servername = match extra.as_ref() {
		Some(extra) => match extra.get::<_, Option<LuaString>>("servername") {
			Ok(Some(v)) => match webpki::DNSNameRef::try_from_ascii(v.as_bytes()) {
				Ok(v) => Some(v.to_owned()),
				Err(e) => return Ok(Err(format!("servername is not a DNSName: {}", e))),
			},
			Ok(None) => None,
			Err(e) => return Ok(Err(format!("invalid option servername (required for TLS, and TLS context is given): {}", e))),
		},
		None => None,
	};

	let tls_ctx_arc = tls_ctx.map(|x| { x.0 });
	let tls_ctx_ref = tls_ctx_arc.as_ref().map(|x| { &**x });

	let tls_state = match (tls_ctx_ref, servername) {
		(Some(tls::TlsConfig::Client{cfg, recorder}), Some(name)) => {
			CachedTlsState::MayConnect(name, cfg.clone(), recorder.clone())
		},
		(Some(tls::TlsConfig::Client{..}), None) => {
			return Ok(Err(format!("client-side TLS context given, but no target server name")))
		},
		(Some(tls::TlsConfig::Server{cfg, ..}), _) => {
			CachedTlsState::MayAccept(cfg.clone())
		},
		(None, _) => {
			CachedTlsState::NoConfig
		},
	};

	with_runtime_lua!{
		let sock = TcpStream::from_std(sock)?;
		let handle = ConnectionHandle::wrap_state(lua, ConnectionState::Plain{sock}, listeners.clone(), (addr, port), tls_state)?;
		match listeners.get::<&'static str, Option<LuaFunction>>("onconnect")? {
			Some(func) => {
				func.call::<_, ()>(handle.clone())?;
			},
			None => (),
		};
		Ok(Ok(handle))
	}
}

pub(crate) fn addclient<'l>(
		lua: &'l Lua,
		(addr, port, listeners, read_size, tls_ctx, _typ, extra): (LuaValue, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaString>, Option<LuaTable>)
		) -> LuaResult<Result<LuaAnyUserData<'l>, String>>
{
	// TODO: honour the typ somehow? :)
	let addr = strerror_ok!(conversion::to_ipaddr(&addr));
	let addr = SocketAddr::new(addr, port);

	let tls_ctx = match tls_ctx {
		None => None,
		Some(tls_ctx) => match &*tls_ctx.0 {
			tls::TlsConfig::Client{cfg, ..} => Some(cfg.clone()),
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
		(Some(_), None) => {
			return Ok(Err(format!("cannot connect via TLS without a servername")))
		},
		(None, None) | (None, Some(_)) => None,
	};

	with_runtime_lua!{
		Ok(Ok(ConnectionHandle::connect(lua, addr, listeners, read_size, tls_config)?))
	}
}
