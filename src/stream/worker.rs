use std::fmt;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut, BufMut, buf::Limit};

use tokio::select;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use tokio_rustls::{
	TlsAcceptor,
	TlsConnector,
	server,
	client,
};

use pin_project_lite::pin_project;

use crate::config;
use crate::conversion::opaque;
use crate::core::{
	MAIN_CHANNEL,
	Message,
	Spawn,
	LuaRegistryHandle,
};
use crate::ioutil::{
	iotimeout,
};
use crate::verify;

use super::msg::{
	ControlMessage,
	SocketOption,
};


pin_project! {
	#[project = ConnectionStateProj]
	pub(super) enum ConnectionState {
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
		match iotimeout(handshake_timeout, acceptor.accept(sock), "STARTTLS handshake timed out").await {
			Ok(sock) => {
				*self = Self::TlsServer{
					sock,
				};
				Ok(())
			},
			Err(e) => {
				// kaboom, break the thing
				*self = Self::Broken{e: Some(Box::new(
					opaque(format!("failed to accept TLS connection: {}", e))
				))};
				Err(e)
			},
		}
	}

	async fn starttls_client(&mut self, sock: TcpStream, name: webpki::DNSNameRef<'_>, connector: TlsConnector, recorder: &verify::RecordingVerifier, handshake_timeout: Duration) -> io::Result<verify::VerificationRecord> {
		let (verify, sock) = recorder.scope(async move {
			iotimeout(handshake_timeout, connector.connect(name, sock), "STARTTLS handshake timed out").await
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
					opaque(format!("failed to initiate TLS connection: {}", e))
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

pub(super) struct StreamWorker {
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

impl StreamWorker {
	pub(super) fn new(
			rx: mpsc::UnboundedReceiver<ControlMessage>,
			conn: ConnectionState,
			cfg: config::StreamConfig,
			handle: LuaRegistryHandle
	) -> Self {
		Self{
			rx,
			conn,
			cfg,
			handle,
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
			tx_buf: None,
			buf: None,
		}
	}

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

impl Spawn for StreamWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}
