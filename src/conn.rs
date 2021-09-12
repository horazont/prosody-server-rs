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
use std::time::Duration;

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
use crate::core::{
	MAIN_CHANNEL,
	Message,
	Spawn,
	LuaRegistryHandle,
	may_call_listener,
};
use crate::tls;
use crate::conversion;
use crate::verify;
use crate::cert;
use crate::config;
use crate::config::CONFIG;
use crate::ioutil::flattened_timeout;


#[derive(Clone)]
pub(crate) enum PreTlsConfig {
	None,
	ClientSide(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>),
	ServerSide(Arc<rustls::ServerConfig>),
}

impl fmt::Debug for PreTlsConfig {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::None => write!(f, "PreTlsConfig::None"),
			Self::ClientSide(name, _, _) => write!(f, "PreTlsConfig::ClientSide({:?})", name),
			Self::ServerSide(_) => write!(f, "PreTlsConfig::ServerSide(..)"),
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum StateTransitionError {
	TlsAlreadyConfirmed,
	TlsInProgress,
	TlsEstablished,
	ContextRequired,
	PeerNameRequired,
	NotConnected,
	Failed,
}

impl fmt::Display for StateTransitionError {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::TlsAlreadyConfirmed => f.write_str("invalid operation: TLS already confirmed"),
			Self::TlsInProgress => f.write_str("invalid operation: TLS handshake in progress"),
			Self::TlsEstablished => f.write_str("invalid operation: TLS already established"),
			Self::ContextRequired => f.write_str("incomplete config: cannot start TLS without a context"),
			Self::PeerNameRequired => f.write_str("incomplete config: peer name required to initiate TLS"),
			Self::NotConnected => f.write_str("invalid state: not connected"),
			Self::Failed => f.write_str("connection handle poisoned"),
		}
	}
}

impl std::error::Error for StateTransitionError {}

impl From<StateTransitionError> for LuaError {
	fn from(other: StateTransitionError) -> Self {
		LuaError::ExternalError(Arc::new(other))
	}
}

/**
Describes the stream state.

This is used for orchestrating the Lua callbacks on state transitions and to figure out which actions are currently allowed.
*/
#[derive(Debug, Clone)]
pub(crate) enum StreamState {
	/// The connection is not established yet.
	///
	/// Only for sockets created through addclient.
	Connecting(PreTlsConfig),

	/// The connection is established, no TLS has been negotiated yet.
	///
	/// Future TLS negotiation is possible based on a call to starttls and possible available state.
	Plain(PreTlsConfig),

	/// The TLS handshake has been started through starttls() or while establishing the connection.
	TlsHandshaking,

	/// The TLS handshake has completed.
	Tls{
		verify: verify::VerificationRecord,
	},

	/// The connection has been closed either locally or remotely.
	Disconnected,

	/// The connection broke internally during a state change.
	Failed,
}

impl StreamState {
	#[inline]
	fn transition_impl<T, F: FnOnce(Self) -> Result<(Self, T), (Self, StateTransitionError)>>(&mut self, f: F) -> Result<T, StateTransitionError> {
		let mut tmp = Self::Failed;
		std::mem::swap(&mut tmp, self);
		let result = match f(tmp) {
			Ok((new, v)) => {
				tmp = new;
				Ok(v)
			},
			Err((new, err)) => {
				tmp = new;
				Err(err)
			},
		};
		std::mem::swap(&mut tmp, self);
		result
	}

	pub(crate) fn connect<'l>(&mut self) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| {
			match this {
				Self::Connecting(tls) => {
					Ok((Self::Plain(tls), true))
				},
				_ => Ok((this, false)),
			}
		})
	}

	pub(crate) fn confirm_tls<'l>(&mut self, verify: verify::VerificationRecord) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| {
			match this {
				Self::TlsHandshaking | Self::Plain(..) => {
					Ok((Self::Tls{verify}, false))
				},
				Self::Connecting(..) => {
					Ok((Self::Tls{verify}, true))
				},
				Self::Disconnected => Err((this, StateTransitionError::NotConnected)),
				Self::Failed => Err((this, StateTransitionError::Failed)),
				Self::Tls{..} => Err((this, StateTransitionError::TlsAlreadyConfirmed)),
			}
		})
	}

	pub(crate) fn disconnect<'l>(&mut self) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| {
			match this {
				Self::Disconnected => Ok((this, false)),
				_ => Ok((Self::Disconnected, true)),
			}
		})
	}

	fn start_tls(&mut self, given_config: Option<&tls::TlsConfig>, given_servername: Option<webpki::DNSNameRef>) -> Result<ControlMessage, StateTransitionError> {
		self.transition_impl(|this| {
			let tls_config = match this {
				Self::TlsHandshaking => return Err((this, StateTransitionError::TlsInProgress)),
				Self::Tls{..} => return Err((this, StateTransitionError::TlsEstablished)),
				Self::Failed => return Err((this, StateTransitionError::Failed)),
				Self::Connecting(_) | Self::Disconnected => return Err((this, StateTransitionError::NotConnected)),
				Self::Plain(ref tls) => tls,
			};

			let msg = match tls_config {
				PreTlsConfig::None => match given_config {
					// We can only *accept* connections based on the given config, as we lack a target hostname
					Some(tls::TlsConfig::Client{cfg, recorder}) => match given_servername {
						Some(v) => ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone()),
						None => return Err((this, StateTransitionError::PeerNameRequired)),
					},
					Some(tls::TlsConfig::Server{cfg, ..}) => ControlMessage::AcceptTls(cfg.clone()),
					None => return Err((this, StateTransitionError::ContextRequired)),
				},
				PreTlsConfig::ServerSide(cfg) => match given_config {
					// We can only *accept* connections based on the given config, as we lack a target hostname
					Some(tls::TlsConfig::Client{cfg, recorder}) => match given_servername {
						Some(v) => ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone()),
						None => return Err((this, StateTransitionError::PeerNameRequired)),
					},
					Some(tls::TlsConfig::Server{cfg, ..}) => ControlMessage::AcceptTls(cfg.clone()),
					None => ControlMessage::AcceptTls(cfg.clone()),
				},
				PreTlsConfig::ClientSide(name, cfg, recorder) => {
					let name = match given_servername {
						Some(name) => name.to_owned(),
						None => name.clone(),
					};
					match given_config {
						// We can only *accept* connections based on the given config, as we lack a target hostname
						Some(tls::TlsConfig::Client{cfg, recorder}) => ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone()),
						Some(tls::TlsConfig::Server{cfg, ..}) => ControlMessage::AcceptTls(cfg.clone()),
						None => ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone()),
					}
				},
			};

			Ok((StreamState::TlsHandshaking, msg))
		})
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
	state: StreamState,
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
			Ok(match this.state {
				StreamState::Tls{..} => true,
				_ => false,
			})
		});

		methods.add_method("ssl_info", |_, _this: &Self, _: ()| -> LuaResult<()> {
			// TODO: return something useful here
			Ok(())
		});

		methods.add_method("ssl_peercertificate", |_, this, _: ()| -> LuaResult<Option<cert::ParsedCertificate>> {
			match &this.state {
				StreamState::Tls{verify, ..} => match verify {
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
			match &this.state {
				StreamState::Tls{verify, ..} => match verify {
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
			let msg = this.state.start_tls(ctx_ref, servername_ref)?;
			match this.tx.send(msg) {
				Ok(()) => Ok(()),
				Err(_) => return Err(LuaError::RuntimeError("channel gone!".to_string())),
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
	fn wrap_state<'l>(
			lua: &'l Lua,
			conn: ConnectionState,
			listeners: LuaTable,
			addr: (String, u16),
			state: StreamState,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			state,
			sockaddr: addr.0,
			sockport: addr.1,
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		ConnectionWorker{
			rx,
			conn,
			cfg,
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
			tx_buf: None,
			handle,
			buf: None,
		}.spawn();
		Ok(v)
	}

	fn connect<'l>(
			lua: &'l Lua,
			addr: SocketAddr,
			listeners: LuaTable,
			tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
			connect_cfg: config::ClientConfig,
			stream_cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			// we might establish TLS right away, in that case it doesn't matter
			state: StreamState::Connecting(PreTlsConfig::None),
			// this is actually correct because ip() is supposed to return the remote IP for clients
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		ConnectWorker{
			rx,
			addr,
			tls_config,
			connect_cfg,
			stream_cfg,
			handle,
		}.spawn();
		Ok(v)
	}

	pub(crate) fn wrap_plain<'l>(
			lua: &'l Lua,
			conn: TcpStream,
			listeners: LuaTable,
			addr: Option<SocketAddr>,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::Plain{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), StreamState::Plain(PreTlsConfig::None), cfg)
	}

	pub(crate) fn wrap_tls_server<'l>(
			lua: &'l Lua,
			conn: server::TlsStream<TcpStream>,
			listeners: LuaTable,
			addr: Option<SocketAddr>,
			verify: verify::VerificationRecord,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.get_ref().0.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::TlsServer{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), StreamState::Tls{verify}, cfg)
	}

	pub(crate) fn state_mut(&mut self) -> &mut StreamState {
		&mut self.state
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

	async fn starttls_server(&mut self, sock: TcpStream, acceptor: TlsAcceptor, handshake_timeout: Duration) -> io::Result<()> {
		match flattened_timeout(handshake_timeout, acceptor.accept(sock), "STARTTLS handshake timed out").await {
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

	async fn starttls_client(&mut self, sock: TcpStream, name: webpki::DNSNameRef<'_>, connector: TlsConnector, recorder: &verify::RecordingVerifier, handshake_timeout: Duration) -> io::Result<verify::VerificationRecord> {
		let (verify, sock) = recorder.scope(async move {
			flattened_timeout(handshake_timeout, connector.connect(name, sock), "STARTTLS handshake timed out").await
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

	async fn starttls_connect(&mut self, name: webpki::DNSNameRef<'_>, ctx: Arc<rustls::ClientConfig>, recorder: &verify::RecordingVerifier, handshake_timeout: Duration) -> io::Result<verify::VerificationRecord> {
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
				self.starttls_client(sock, name, ctx.into(), recorder, handshake_timeout).await
			},
		}
	}

	async fn starttls_accept(&mut self, ctx: Arc<rustls::ServerConfig>, handshake_timeout: Duration) -> io::Result<()> {
		let mut tmp = ConnectionState::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsServer{..} | Self::TlsClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::Plain{sock} => self.starttls_server(sock, ctx.into(), handshake_timeout).await,
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
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	conn: ConnectionState,
	cfg: config::StreamConfig,
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
				let result = match MAIN_CHANNEL.send(Message::Incoming{
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
		match MAIN_CHANNEL.send(Message::ReadClosed{handle: self.handle.clone()}).await {
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
				self.conn.shutdown().await?;
				MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle.clone(), error: None}).await;
				Ok(MsgResult::Exit)
			},
			ControlMessage::SetOption(option) => {
				match option {
					SocketOption::KeepAlive(enabled) => self.set_keepalive(enabled)?,
				};
				Ok(MsgResult::Continue)
			},
			ControlMessage::AcceptTls(ctx) => {
				self.conn.starttls_accept(ctx, self.cfg.ssl_handshake_timeout).await?;
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), verify: verify::VerificationRecord::Unverified}).await {
					Ok(_) => {
						self.rx_mode = self.rx_mode.unblock();
						self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::ConnectTls(name, ctx, recorder) => {
				let verify = self.conn.starttls_connect(name.as_ref(), ctx, &*recorder, self.cfg.ssl_handshake_timeout).await?;
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), verify}).await {
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
					_ = MAIN_CHANNEL.closed() => return,
				}
			}

			select! {
				result = read_with_buf(&mut self.conn, &mut self.buf, self.cfg.read_size), if self.rx_mode.may() => match result {
					Ok(buf) => match self.proc_read_buffer(buf).await {
						Ok(ReadResult::Closed) => {
							self.rx_mode = DirectionMode::Closed;
						},
						Ok(ReadResult::Continue) => (),
						Err(()) => return,
					},
					Err(e) => {
						MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle, error: Some(Box::new(e))}).await;
						return
					},
				},
				msg = self.rx.recv() => match msg {
					Some(msg) => match self.proc_msg(msg).await {
						Ok(MsgResult::Exit) => return,
						Ok(MsgResult::Continue) => (),
						Err(e) => {
							MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle, error: Some(Box::new(e))}).await;
							return
						},
					},
					None => return,
				},
				_ = MAIN_CHANNEL.closed() => return,
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
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	addr: SocketAddr,
	connect_cfg: config::ClientConfig,
	stream_cfg: config::StreamConfig,
	tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
	handle: LuaRegistryHandle,
}

impl ConnectWorker {
	async fn run(self) {
		let sock = match flattened_timeout(self.connect_cfg.connect_timeout, TcpStream::connect(self.addr), "connection timed out").await {
			Ok(sock) => sock,
			Err(e) => {
				MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
					handle: self.handle,
					error: Some(Box::new(e)),
				}).await;
				return;
			},
		};
		let conn = match self.tls_config {
			Some((name, config, recorder)) => {
				let connector: TlsConnector = config.into();
				let handshake_timeout = self.stream_cfg.ssl_handshake_timeout;
				let (verify, result) = recorder.scope(async move {
					flattened_timeout(handshake_timeout, connector.connect(name.as_ref(), sock), "timeout during TLS handshake").await
				}).await;
				let sock = match result {
					Ok(sock) => sock,
					Err(e) => {
						MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
							handle: self.handle,
							error: Some(Box::new(e)),
						}).await;
						return;
					},
				};
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), verify}).await {
					Ok(_) => (),
					// can only happen during shutdown, drop it.
					Err(_) => return,
				};
				ConnectionState::TlsClient{sock}
			},
			None => {
				match MAIN_CHANNEL.send(Message::Connect{handle: self.handle.clone()}).await {
					Ok(_) => (),
					// can only happen during shutdown, drop it.
					Err(_) => return,
				};
				ConnectionState::Plain{sock}
			}
		};
		return ConnectionWorker{
			rx: self.rx,
			cfg: self.stream_cfg,
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
		(fd, addr, port, listeners, read_size, tls_ctx, extra): (RawFd, String, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaTable>)
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
			PreTlsConfig::ClientSide(name, cfg.clone(), recorder.clone())
		},
		(Some(tls::TlsConfig::Client{..}), None) => {
			return Ok(Err(format!("client-side TLS context given, but no target server name")))
		},
		(Some(tls::TlsConfig::Server{cfg, ..}), _) => {
			PreTlsConfig::ServerSide(cfg.clone())
		},
		(None, _) => PreTlsConfig::None,
	};

	let mut cfg = CONFIG.read().unwrap().stream;
	cfg.read_size = read_size;

	with_runtime_lua!{
		let sock = TcpStream::from_std(sock)?;
		let handle = ConnectionHandle::wrap_state(lua, ConnectionState::Plain{sock}, listeners.clone(), (addr, port), StreamState::Plain(tls_state), cfg)?;
		may_call_listener(&listeners, "onconnect", handle.clone())?;
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
			tls::TlsConfig::Client{cfg, recorder} => Some((cfg.clone(), recorder.clone())),
			_ => return Ok(Err(format!("non-client TLS config passed to client socket"))),
		}
	};

	// extra is required, we MUST have the server name...
	let tls_config = match (tls_ctx, extra.as_ref()) {
		(Some((cfg, recorder)), Some(extra)) => {
			let servername = match extra.get::<_, Option<LuaString>>("servername") {
				Ok(Some(v)) => v,
				Ok(None) => return Ok(Err(format!("missing option servername (required for TLS, and TLS context is given)"))),
				Err(e) => return Ok(Err(format!("invalid option servername (required for TLS, and TLS context is given): {}", e))),
			};
			let servername = match webpki::DNSNameRef::try_from_ascii(servername.as_bytes()) {
				Ok(v) => v,
				Err(e) => return Ok(Err(format!("servername is not a DNSName: {}", e))),
			};
			Some((servername.to_owned(), cfg, recorder))
		},
		(Some(_), None) => {
			return Ok(Err(format!("cannot connect via TLS without a servername")))
		},
		(None, None) | (None, Some(_)) => None,
	};

	let (connect_cfg, mut stream_cfg) = {
		let config = CONFIG.read().unwrap();
		(config.client, config.stream)
	};
	stream_cfg.read_size = read_size;

	with_runtime_lua!{
		Ok(Ok(ConnectionHandle::connect(lua, addr, listeners, tls_config, connect_cfg, stream_cfg)?))
	}
}
