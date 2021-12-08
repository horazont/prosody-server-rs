use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;

use tokio::select;
use tokio::io::{
	AsyncRead,
	AsyncWrite,
	AsyncWriteExt,
	ReadBuf,
};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use tokio_rustls::{
	TlsAcceptor,
	TlsConnector,
	server,
	client,
	rustls,
};

use futures_util::StreamExt;

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
	Duplex,
	DuplexResult,
	ReadResult,
	AsyncReadable,
};
use crate::tls;
use crate::verify;

use super::msg::{
	ControlMessage,
	SocketOption,
};
use super::handle::AddrStr;


pin_project! {
	#[project = StreamProj]
	pub(super) enum Stream {
		Broken{e: Option<Box<dyn std::error::Error + Send + 'static>>},
		PlainTcp{
			#[pin]
			conn: TcpStream,
		},
		PlainUnix{
			#[pin]
			conn: UnixStream
		},
		TlsTcpServer{
			#[pin]
			conn: server::TlsStream<TcpStream>,
		},
		TlsTcpClient{
			#[pin]
			conn: client::TlsStream<TcpStream>,
		},
		TlsUnixServer{
			#[pin]
			conn: server::TlsStream<UnixStream>,
		},
		TlsUnixClient{
			#[pin]
			conn: client::TlsStream<UnixStream>,
		},
	}
}

impl From<TcpStream> for Stream {
	fn from(other: TcpStream) -> Self {
		Self::PlainTcp{conn: other}
	}
}

impl From<UnixStream> for Stream {
	fn from(other: UnixStream) -> Self {
		Self::PlainUnix{conn: other}
	}
}

impl From<server::TlsStream<TcpStream>> for Stream {
	fn from(other: server::TlsStream<TcpStream>) -> Self {
		Self::TlsTcpServer{conn: other}
	}
}

impl From<client::TlsStream<TcpStream>> for Stream {
	fn from(other: client::TlsStream<TcpStream>) -> Self {
		Self::TlsTcpClient{conn: other}
	}
}

impl From<client::TlsStream<UnixStream>> for Stream {
	fn from(other: client::TlsStream<UnixStream>) -> Self {
		Self::TlsUnixClient{conn: other}
	}
}

impl From<server::TlsStream<UnixStream>> for Stream {
	fn from(other: server::TlsStream<UnixStream>) -> Self {
		Self::TlsUnixServer{conn: other}
	}
}

impl fmt::Debug for Stream {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Broken{e} => f.debug_struct("Stream::Broken").field("e", &e).finish(),
			Self::PlainTcp{..} => f.debug_struct("Stream::PlainTcp").finish_non_exhaustive(),
			Self::PlainUnix{..} => f.debug_struct("Stream::PlainUnix").finish_non_exhaustive(),
			Self::TlsTcpServer{..} => f.debug_struct("Stream::TlsTcpServer").finish_non_exhaustive(),
			Self::TlsTcpClient{..} => f.debug_struct("Stream::TlsTcpClient").finish_non_exhaustive(),
			Self::TlsUnixServer{..} => f.debug_struct("Stream::TlsUnixServer").finish_non_exhaustive(),
			Self::TlsUnixClient{..} => f.debug_struct("Stream::TlsUnixClient").finish_non_exhaustive(),
		}
	}
}

impl Stream {
	fn broken_err(e: &Option<Box<dyn std::error::Error + Send + 'static>>) -> io::Error {
		match e {
			Some(e) => io::Error::new(io::ErrorKind::ConnectionReset, format!("connection invalidated because of a previous failed operation: {}", e)),
			None => io::Error::new(io::ErrorKind::ConnectionReset, "connection invalidated because of a previous failed operation (unknown error)"),
		}
	}

	fn is_valid(&self) -> bool {
		match self {
			Self::Broken{..} => false,
			_ => true,
		}
	}

	async fn starttls_server<T: AsyncRead + AsyncWrite + Unpin>(
		&mut self,
		sock: T,
		acceptor: TlsAcceptor,
		recorder: &verify::RecordingClientVerifier,
		handshake_timeout: Duration,
	) -> io::Result<tls::Info>
		where server::TlsStream<T>: Into<Self>
	{
		let (verify, sock) = recorder.scope(iotimeout(
			handshake_timeout,
			acceptor.accept(sock),
			"STARTTLS handshake timed out",
		)).await;
		match sock {
			Ok(sock) => {
				let handshake = sock.get_ref().1.into();
				*self = sock.into();
				Ok(tls::Info{verify, handshake})
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

	async fn starttls_client<T: AsyncRead + AsyncWrite + Unpin>(
		&mut self,
		sock: T,
		name: rustls::ServerName,
		connector: TlsConnector,
		recorder: &verify::RecordingVerifier,
		handshake_timeout: Duration,
	) -> io::Result<tls::Info>
		where client::TlsStream<T>: Into<Self>
	{
		let (verify, sock) = recorder.scope(iotimeout(
			handshake_timeout,
			connector.connect(name, sock),
			"STARTTLS handshake timed out",
		)).await;
		match sock {
			Ok(sock) => {
				let handshake = sock.get_ref().1.into();
				*self = sock.into();
				Ok(tls::Info{verify, handshake})
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

	async fn starttls_connect(
		&mut self,
		name: rustls::ServerName,
		ctx: Arc<rustls::ClientConfig>,
		recorder: &verify::RecordingVerifier,
		handshake_timeout: Duration
	) -> io::Result<tls::Info> {
		let mut tmp = Stream::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsTcpServer{..} | Self::TlsTcpClient{..} | Self::TlsUnixServer{..} | Self::TlsUnixClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::PlainTcp{conn} => self.starttls_client(conn, name, ctx.into(), recorder, handshake_timeout).await,
			Self::PlainUnix{conn} => self.starttls_client(conn, name, ctx.into(), recorder, handshake_timeout).await,
		}
	}

	async fn starttls_accept(&mut self, ctx: Arc<rustls::ServerConfig>, recorder: &verify::RecordingClientVerifier, handshake_timeout: Duration) -> io::Result<tls::Info> {
		let mut tmp = Stream::Broken{e: None};
		std::mem::swap(&mut tmp, self);
		match tmp {
			Self::Broken{ref e} => {
				let result = Err(Self::broken_err(e));
				*self = tmp;
				result
			},
			Self::TlsTcpServer{..} | Self::TlsTcpClient{..} | Self::TlsUnixServer{..} | Self::TlsUnixClient{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "attempt to start TLS on a socket with TLS")),
			Self::PlainTcp{conn} => self.starttls_server(conn, ctx.into(), recorder, handshake_timeout).await,
			Self::PlainUnix{conn} => self.starttls_server(conn, ctx.into(), recorder, handshake_timeout).await,
		}
	}
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{conn, ..} => conn.poll_read(cx, buf),
            StreamProj::PlainUnix{conn, ..} => conn.poll_read(cx, buf),
            StreamProj::TlsTcpServer{conn, ..} => conn.poll_read(cx, buf),
            StreamProj::TlsTcpClient{conn, ..} => conn.poll_read(cx, buf),
            StreamProj::TlsUnixServer{conn, ..} => conn.poll_read(cx, buf),
            StreamProj::TlsUnixClient{conn, ..} => conn.poll_read(cx, buf),
		}
	}
}

impl AsyncReadable for Stream {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            Self::PlainTcp{conn, ..} => conn.poll_read_ready(cx),
            Self::PlainUnix{conn, ..} => conn.poll_read_ready(cx),
            Self::TlsTcpServer{conn, ..} => conn.poll_read_ready(cx),
            Self::TlsTcpClient{conn, ..} => conn.poll_read_ready(cx),
            Self::TlsUnixServer{conn, ..} => conn.poll_read_ready(cx),
            Self::TlsUnixClient{conn, ..} => conn.poll_read_ready(cx),
		}
	}
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{conn, ..} => conn.poll_write(cx, buf),
            StreamProj::PlainUnix{conn, ..} => conn.poll_write(cx, buf),
            StreamProj::TlsTcpServer{conn, ..} => conn.poll_write(cx, buf),
            StreamProj::TlsTcpClient{conn, ..} => conn.poll_write(cx, buf),
            StreamProj::TlsUnixServer{conn, ..} => conn.poll_write(cx, buf),
            StreamProj::TlsUnixClient{conn, ..} => conn.poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{conn, ..} => conn.poll_write_vectored(cx, bufs),
            StreamProj::PlainUnix{conn, ..} => conn.poll_write_vectored(cx, bufs),
            StreamProj::TlsTcpServer{conn, ..} => conn.poll_write_vectored(cx, bufs),
            StreamProj::TlsTcpClient{conn, ..} => conn.poll_write_vectored(cx, bufs),
            StreamProj::TlsUnixServer{conn, ..} => conn.poll_write_vectored(cx, bufs),
            StreamProj::TlsUnixClient{conn, ..} => conn.poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{conn, ..} => conn.poll_flush(cx),
            StreamProj::PlainUnix{conn, ..} => conn.poll_flush(cx),
            StreamProj::TlsTcpServer{conn, ..} => conn.poll_flush(cx),
            StreamProj::TlsTcpClient{conn, ..} => conn.poll_flush(cx),
            StreamProj::TlsUnixServer{conn, ..} => conn.poll_flush(cx),
            StreamProj::TlsUnixClient{conn, ..} => conn.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{conn, ..} => conn.poll_shutdown(cx),
            StreamProj::PlainUnix{conn, ..} => conn.poll_shutdown(cx),
            StreamProj::TlsTcpServer{conn, ..} => conn.poll_shutdown(cx),
            StreamProj::TlsTcpClient{conn, ..} => conn.poll_shutdown(cx),
            StreamProj::TlsUnixServer{conn, ..} => conn.poll_shutdown(cx),
            StreamProj::TlsUnixClient{conn, ..} => conn.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Broken{..} => false,
            Self::PlainTcp{conn, ..} => conn.is_write_vectored(),
            Self::PlainUnix{conn, ..} => conn.is_write_vectored(),
            Self::TlsTcpServer{conn, ..} => conn.is_write_vectored(),
            Self::TlsTcpClient{conn, ..} => conn.is_write_vectored(),
            Self::TlsUnixServer{conn, ..} => conn.is_write_vectored(),
            Self::TlsUnixClient{conn, ..} => conn.is_write_vectored(),
        }
    }
}

pub(super) enum AnyStream {
	Tcp(std::net::TcpStream),
	Unix(std::os::unix::net::UnixStream),
}

impl AnyStream {
	pub(super) fn try_from_raw_fd(fd: RawFd) -> io::Result<Self> {
		// Safety: We check that this is a socket FD by calling getsockopt later and we'll also assert the correct address family'
		let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
		if sock.r#type()? != socket2::Type::STREAM {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"attempt to pass non-stream socket to FdStream",
			));
		}
		sock.set_nonblocking(true)?;
		match sock.domain()? {
			socket2::Domain::IPV4 | socket2::Domain::IPV6 => {
				Ok(Self::Tcp(sock.into()))
			},
			socket2::Domain::UNIX => {
				Ok(Self::Unix(sock.into()))
			},
			_ => Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"unsupported socket domain",
			)),
		}
	}

	pub(super) fn local_addr_str(&self) -> io::Result<AddrStr> {
		match self {
			Self::Tcp(sock) => Ok(sock.local_addr()?.into()),
			Self::Unix(sock) => Ok(sock.local_addr()?.into()),
		}
	}
}

pin_project! {
	#[derive(Debug)]
	pub(super) struct FdStream {
		fd: RawFd,
		#[pin]
		inner: Stream,
	}
}

impl AsRawFd for FdStream {
	fn as_raw_fd(&self) -> RawFd {
		if !self.inner.is_valid() {
			panic!("attempt to get FD from broken stream")
		}
		self.fd
	}
}

impl From<TcpStream> for FdStream {
	fn from(other: TcpStream) -> Self {
		Self{
			fd: other.as_raw_fd(),
			inner: other.into(),
		}
	}
}

impl From<UnixStream> for FdStream {
	fn from(other: UnixStream) -> Self {
		Self{
			fd: other.as_raw_fd(),
			inner: other.into(),
		}
	}
}

impl TryFrom<AnyStream> for FdStream {
	type Error = io::Error;

	fn try_from(other: AnyStream) -> Result<Self, Self::Error> {
		match other {
			AnyStream::Tcp(sock) => {
				let sock = TcpStream::from_std(sock)?;
				Ok(sock.into())
			},
			AnyStream::Unix(sock) => {
				let sock = UnixStream::from_std(sock)?;
				Ok(sock.into())
			},
		}
	}
}

impl From<server::TlsStream<TcpStream>> for FdStream {
	fn from(other: server::TlsStream<TcpStream>) -> Self {
		Self{
			fd: other.get_ref().0.as_raw_fd(),
			inner: other.into(),
		}
	}
}

impl From<client::TlsStream<TcpStream>> for FdStream {
	fn from(other: client::TlsStream<TcpStream>) -> Self {
		Self{
			fd: other.get_ref().0.as_raw_fd(),
			inner: other.into(),
		}
	}
}

impl Deref for FdStream {
	type Target = Stream;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl DerefMut for FdStream {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner
	}
}

impl AsyncRead for FdStream {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		this.inner.poll_read(cx, buf)
	}
}

impl AsyncWrite for FdStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        this.inner.poll_write(cx, buf)
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.project();
        this.inner.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
		self.inner.is_write_vectored()
    }
}

impl AsyncReadable for FdStream {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.inner.poll_read_ready(cx)
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

pin_project! {
	#[project = StreamWorkerProj]
	pub(super) struct StreamWorker {
		rx: mpsc::UnboundedReceiver<ControlMessage>,
		cfg: config::StreamConfig,
		#[pin]
		stream: Duplex<FdStream, VecDeque<Bytes>>,
		rx_mode: DirectionMode,
		tx_mode: DirectionMode,
		handle: LuaRegistryHandle,
	}
}

impl StreamWorkerProj<'_> {
	fn get_fdstream_mut(&mut self) -> &mut FdStream {
		self.stream.as_mut().get_pin_mut().0
	}

	fn set_keepalive(&self, enabled: bool) -> Result<(), io::Error> {
		nix::sys::socket::setsockopt(
			self.stream.as_ref().get_pin().0.as_raw_fd(),
			nix::sys::socket::sockopt::KeepAlive,
			&enabled,
		)?;
		Ok(())
	}

	async fn force_flush(&mut self) -> io::Result<()> {
		let (stream, q) = self.stream.as_mut().get_pin_mut();
		for mut buf in q.drain(..) {
			iotimeout(self.cfg.send_timeout, stream.write_all_buf(&mut buf), "write timed out").await?;
		}
		iotimeout(self.cfg.send_timeout, stream.flush(), "flush timed out").await?;
		Ok(())
	}

	async fn clean_shutdown(&mut self) -> io::Result<()> {
		match self.force_flush().await {
			// ignore any errors here, we're doing a shutdown. this is best
			// effort.
			Ok(..) | Err(..) => (),
		};
		self.get_fdstream_mut().shutdown().await
	}

	async fn clean_shutdown_with_msg(
		&mut self,
		err: Option<Box<dyn std::error::Error + Send + 'static>>,
	) {
		let shutdown_err = self.clean_shutdown().await.err();
		let err = err.or(match shutdown_err {
			Some(x) => Some(Box::new(x)),
			None => None,
		});
		MAIN_CHANNEL.fire_and_forget(
			Message::Disconnect{
				handle: self.handle.clone(),
				error: err,
			},
		).await;
	}

	#[inline]
	async fn proc_msg(
		&mut self,
		msg: ControlMessage,
	) -> io::Result<MsgResult> {
		match msg {
			ControlMessage::Close => {
				self.clean_shutdown_with_msg(None).await;
				Ok(MsgResult::Exit)
			},
			ControlMessage::SetOption(option) => {
				match option {
					SocketOption::KeepAlive(enabled) => self.set_keepalive(enabled)?,
				};
				Ok(MsgResult::Continue)
			},
			ControlMessage::AcceptTls(ctx, recorder) => {
				self.force_flush().await?;
				let timeout = self.cfg.ssl_handshake_timeout;
				let tls_info = self.get_fdstream_mut().starttls_accept(
					ctx,
					&recorder,
					timeout,
				).await?;
				match MAIN_CHANNEL.send(
					Message::TlsStarted{handle: self.handle.clone(), tls_info},
				).await {
					Ok(_) => {
						*self.rx_mode = self.rx_mode.unblock();
						*self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::ConnectTls(name, ctx, recorder) => {
				let timeout = self.cfg.ssl_handshake_timeout;
				let tls_info = self.get_fdstream_mut().starttls_connect(
					name,
					ctx,
					&*recorder,
					timeout,
				).await?;
				match MAIN_CHANNEL.send(
					Message::TlsStarted{handle: self.handle.clone(), tls_info},
				).await {
					Ok(_) => {
						*self.rx_mode = self.rx_mode.unblock();
						*self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::Write(buf) => if self.tx_mode.may_ever() {
				self.stream.as_mut().get_pin_mut().1.push_back(buf);
				Ok(MsgResult::Continue)
			} else {
				// should this instead be a write error or something?!
				Ok(MsgResult::Continue)
			},
			ControlMessage::BlockReads => {
				*self.rx_mode = self.rx_mode.block();
				Ok(MsgResult::Continue)
			}
			ControlMessage::BlockWrites => {
				*self.tx_mode = self.tx_mode.block();
				Ok(MsgResult::Continue)
			},
			ControlMessage::UnblockWrites => {
				*self.tx_mode = self.tx_mode.unblock();
				Ok(MsgResult::Continue)
			},
		}
	}
}

impl StreamWorker {
	pub(super) fn new(
			rx: mpsc::UnboundedReceiver<ControlMessage>,
			conn: FdStream,
			cfg: config::StreamConfig,
			handle: LuaRegistryHandle
	) -> Self {
		Self{
			rx,
			cfg,
			handle,
			stream: Duplex::new(conn, VecDeque::new(), cfg.read_timeout, cfg.send_timeout),
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
		}
	}

	async fn run(self: Pin<&mut Self>) {
		let mut this = self.project();
		loop {
			if !this.rx_mode.may_ever() && !this.tx_mode.may_ever() {
				// if the connection can neither read nor write ever again, we only shutdown and then bail out
				select! {
					_ = this.stream.as_mut().get_pin_mut().0.shutdown() => return,
					_ = MAIN_CHANNEL.closed() => return,
				}
			}
			this.stream.as_mut().set_may_read(this.rx_mode.may());
			this.stream.as_mut().set_may_write(this.tx_mode.may());
			select! {
				result = this.stream.next() => {
					let DuplexResult{
						read_result,
						write_result,
					} = result.expect("Duplex always returns something");
					match read_result {
						// some data received
						ReadResult::Ok(buf) => {
							match MAIN_CHANNEL.send(Message::Incoming{
								handle: this.handle.clone(),
								data: buf,
							}).await {
								Ok(_) => (),
								// again, only during shutdown
								Err(_) => return,
							};
						},
						ReadResult::Eof => {
							*this.rx_mode = DirectionMode::Closed;
							// we flush our current buffers and then we exit
							this.clean_shutdown_with_msg(None).await;
							return;
						},
						// other reason for the return, we don't care
						ReadResult::NoRead => (),
						// read timeout
						ReadResult::Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
							let (reply_tx, reply_rx) = oneshot::channel();
							// if it does not really get sent, the reply_rx will
							// complete immediately because the tx got dropped and
							// thus the connection will be closed because of the
							// read timeout. perfect.
							MAIN_CHANNEL.fire_and_forget(Message::ReadTimeout{
								handle: this.handle.clone(),
								keepalive: reply_tx,
							}).await;

							match reply_rx.await {
								Ok(true) => {
									// XXX: this prohibits changing the read timeout from the callback... Might want to return a duration instead.
									let read_deadline = Instant::now() + this.cfg.read_timeout;
									this.stream.as_mut().set_read_deadline(read_deadline.into());
								},
								Ok(false) | Err(_) => {
									MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
										handle: this.handle.clone(),
										error: Some(Box::new(io::Error::new(
											io::ErrorKind::TimedOut,
											"read timeout",
										))),
									}).await;
									// it's dead jim.
									return;
								},
							}
						},
						// other read error
						ReadResult::Err(e) => {
							MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
								handle: this.handle.clone(),
								error: Some(Box::new(e)),
							}).await;
							return;
						},
					};
					match write_result {
						// other reason for return
						Ok(()) => (),
						// write error
						Err(e) => {
							MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
								handle: this.handle.clone(),
								error: Some(Box::new(e)),
							}).await;
							return;
						},
					};
				},
				msg = this.rx.recv() => match msg {
					Some(msg) => match this.proc_msg(msg).await {
						Ok(MsgResult::Exit) => return,
						Ok(MsgResult::Continue) => (),
						Err(e) => {
							MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: this.handle.clone(), error: Some(Box::new(e))}).await;
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
		let mut this = Box::pin(self);
		tokio::spawn(async move { this.as_mut().run().await });
	}
}
