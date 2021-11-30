use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pin_utils::pin_mut;

use bytes::{Bytes, BytesMut, BufMut, Buf, buf::Limit};

use tokio::select;
use tokio::io::{
	AsyncRead,
	AsyncReadExt,
	AsyncWrite,
	AsyncWriteExt,
	ReadBuf,
	ReadHalf,
	WriteHalf,
};
use tokio::net::{TcpStream, UnixStream};
use tokio::net::{tcp, unix};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::timeout_at;

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
	iodeadline,
};
use crate::tls;
use crate::verify;

use super::msg::{
	ControlMessage,
	SocketOption,
};


pin_project! {
	#[project = StreamProj]
	pub(super) enum Stream {
		Broken{e: Option<Box<dyn std::error::Error + Send + 'static>>},
		PlainTcp{
			#[pin]
			rx: tcp::OwnedReadHalf,
			#[pin]
			tx: tcp::OwnedWriteHalf,
		},
		PlainUnix{
			#[pin]
			rx: unix::OwnedReadHalf,
			#[pin]
			tx: unix::OwnedWriteHalf,
		},
		TlsTcpServer{
			#[pin]
			rx: ReadHalf<server::TlsStream<TcpStream>>,
			#[pin]
			tx: WriteHalf<server::TlsStream<TcpStream>>,
		},
		TlsTcpClient{
			#[pin]
			rx: ReadHalf<client::TlsStream<TcpStream>>,
			#[pin]
			tx: WriteHalf<client::TlsStream<TcpStream>>,
		},
		TlsUnixServer{
			#[pin]
			rx: ReadHalf<server::TlsStream<UnixStream>>,
			#[pin]
			tx: WriteHalf<server::TlsStream<UnixStream>>,
		},
		TlsUnixClient{
			#[pin]
			rx: ReadHalf<client::TlsStream<UnixStream>>,
			#[pin]
			tx: WriteHalf<client::TlsStream<UnixStream>>,
		},
	}
}

impl From<TcpStream> for Stream {
	fn from(other: TcpStream) -> Self {
		let (rx, tx) = other.into_split();
		Self::PlainTcp{
			rx,
			tx,
		}
	}
}

impl From<UnixStream> for Stream {
	fn from(other: UnixStream) -> Self {
		let (rx, tx) = other.into_split();
		Self::PlainUnix{
			rx,
			tx,
		}
	}
}

impl From<server::TlsStream<TcpStream>> for Stream {
	fn from(other: server::TlsStream<TcpStream>) -> Self {
		let (rx, tx) = tokio::io::split(other);
		Self::TlsTcpServer{
			rx,
			tx,
		}
	}
}

impl From<client::TlsStream<TcpStream>> for Stream {
	fn from(other: client::TlsStream<TcpStream>) -> Self {
		let (rx, tx) = tokio::io::split(other);
		Self::TlsTcpClient{
			rx,
			tx,
		}
	}
}

impl From<client::TlsStream<UnixStream>> for Stream {
	fn from(other: client::TlsStream<UnixStream>) -> Self {
		let (rx, tx) = tokio::io::split(other);
		Self::TlsUnixClient{
			rx,
			tx,
		}
	}
}

impl From<server::TlsStream<UnixStream>> for Stream {
	fn from(other: server::TlsStream<UnixStream>) -> Self {
		let (rx, tx) = tokio::io::split(other);
		Self::TlsUnixServer{
			rx,
			tx,
		}
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
		name: webpki::DNSNameRef<'_>,
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
		name: webpki::DNSNameRef<'_>,
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
			Self::PlainTcp{rx, tx} => {
				let sock = rx.reunite(tx).unwrap();
				self.starttls_client(sock, name, ctx.into(), recorder, handshake_timeout).await
			},
			Self::PlainUnix{rx, tx} => {
				let sock = rx.reunite(tx).unwrap();
				self.starttls_client(sock, name, ctx.into(), recorder, handshake_timeout).await
			},
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
			Self::PlainTcp{rx, tx} => {
				let sock = rx.reunite(tx).unwrap();
				self.starttls_server(sock, ctx.into(), recorder, handshake_timeout).await
			},
			Self::PlainUnix{rx, tx} => {
				let sock = rx.reunite(tx).unwrap();
				self.starttls_server(sock, ctx.into(), recorder, handshake_timeout).await
			},
		}
	}

	fn as_parts_mut(&mut self) -> (&mut (dyn AsyncRead + Unpin + Send + 'static), &mut (dyn AsyncWrite + Unpin + Send + 'static)) {
		match self {
			Self::Broken{ref e} => panic!("broken stream: {:?}", e),
			Self::PlainTcp{ref mut rx, ref mut tx} => (rx, tx),
			Self::PlainUnix{ref mut rx, ref mut tx} => (rx, tx),
			Self::TlsTcpServer{ref mut rx, ref mut tx} => (rx, tx),
			Self::TlsTcpClient{ref mut rx, ref mut tx} => (rx, tx),
			Self::TlsUnixServer{ref mut rx, ref mut tx} => (rx, tx),
			Self::TlsUnixClient{ref mut rx, ref mut tx} => (rx, tx),
		}
	}
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{rx, ..} => rx.poll_read(cx, buf),
            StreamProj::PlainUnix{rx, ..} => rx.poll_read(cx, buf),
            StreamProj::TlsTcpServer{rx, ..} => rx.poll_read(cx, buf),
            StreamProj::TlsTcpClient{rx, ..} => rx.poll_read(cx, buf),
            StreamProj::TlsUnixServer{rx, ..} => rx.poll_read(cx, buf),
            StreamProj::TlsUnixClient{rx, ..} => rx.poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{tx, ..} => tx.poll_write(cx, buf),
            StreamProj::PlainUnix{tx, ..} => tx.poll_write(cx, buf),
            StreamProj::TlsTcpServer{tx, ..} => tx.poll_write(cx, buf),
            StreamProj::TlsTcpClient{tx, ..} => tx.poll_write(cx, buf),
            StreamProj::TlsUnixServer{tx, ..} => tx.poll_write(cx, buf),
            StreamProj::TlsUnixClient{tx, ..} => tx.poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{tx, ..} => tx.poll_write_vectored(cx, bufs),
            StreamProj::PlainUnix{tx, ..} => tx.poll_write_vectored(cx, bufs),
            StreamProj::TlsTcpServer{tx, ..} => tx.poll_write_vectored(cx, bufs),
            StreamProj::TlsTcpClient{tx, ..} => tx.poll_write_vectored(cx, bufs),
            StreamProj::TlsUnixServer{tx, ..} => tx.poll_write_vectored(cx, bufs),
            StreamProj::TlsUnixClient{tx, ..} => tx.poll_write_vectored(cx, bufs),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{tx, ..} => tx.poll_flush(cx),
            StreamProj::PlainUnix{tx, ..} => tx.poll_flush(cx),
            StreamProj::TlsTcpServer{tx, ..} => tx.poll_flush(cx),
            StreamProj::TlsTcpClient{tx, ..} => tx.poll_flush(cx),
            StreamProj::TlsUnixServer{tx, ..} => tx.poll_flush(cx),
            StreamProj::TlsUnixClient{tx, ..} => tx.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        match this {
            StreamProj::Broken{ref e} => Poll::Ready(Err(Self::broken_err(e))),
            StreamProj::PlainTcp{tx, ..} => tx.poll_shutdown(cx),
            StreamProj::PlainUnix{tx, ..} => tx.poll_shutdown(cx),
            StreamProj::TlsTcpServer{tx, ..} => tx.poll_shutdown(cx),
            StreamProj::TlsTcpClient{tx, ..} => tx.poll_shutdown(cx),
            StreamProj::TlsUnixServer{tx, ..} => tx.poll_shutdown(cx),
            StreamProj::TlsUnixClient{tx, ..} => tx.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Broken{..} => false,
            Self::PlainTcp{tx, ..} => tx.is_write_vectored(),
            Self::PlainUnix{tx, ..} => tx.is_write_vectored(),
            Self::TlsTcpServer{tx, ..} => tx.is_write_vectored(),
            Self::TlsTcpClient{tx, ..} => tx.is_write_vectored(),
            Self::TlsUnixServer{tx, ..} => tx.is_write_vectored(),
            Self::TlsUnixClient{tx, ..} => tx.is_write_vectored(),
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
	conn: FdStream,
	cfg: config::StreamConfig,
	buf: Option<Limit<BytesMut>>,
	rx_mode: DirectionMode,
	tx_mode: DirectionMode,
	txq: VecDeque<Bytes>,
	handle: LuaRegistryHandle,
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
			conn,
			cfg,
			handle,
			tx_mode: DirectionMode::Open,
			rx_mode: DirectionMode::Open,
			txq: VecDeque::new(),
			buf: None,
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

	async fn force_flush(&mut self) -> io::Result<()> {
		for mut buf in self.txq.drain(..) {
			iotimeout(self.cfg.send_timeout, self.conn.write_all_buf(&mut buf), "write timed out").await?;
		}
		iotimeout(self.cfg.send_timeout, self.conn.flush(), "flush timed out").await?;
		Ok(())
	}

	async fn clean_shutdown(&mut self) -> io::Result<()> {
		match self.force_flush().await {
			// ignore any errors here, we're doing a shutdown. this is best
			// effort.
			Ok(..) | Err(..) => (),
		};
		self.conn.shutdown().await
	}

	async fn clean_shutdown_with_msg(&mut self, err: Option<Box<dyn std::error::Error + Send + 'static>>) {
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
	async fn proc_msg(&mut self, msg: ControlMessage) -> io::Result<MsgResult> {
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
				let tls_info = self.conn.starttls_accept(ctx, &recorder, self.cfg.ssl_handshake_timeout).await?;
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), tls_info}).await {
					Ok(_) => {
						self.rx_mode = self.rx_mode.unblock();
						self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::ConnectTls(name, ctx, recorder) => {
				let tls_info = self.conn.starttls_connect(name.as_ref(), ctx, &*recorder, self.cfg.ssl_handshake_timeout).await?;
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), tls_info}).await {
					Ok(_) => {
						self.rx_mode = self.rx_mode.unblock();
						self.tx_mode = self.tx_mode.unblock();
						Ok(MsgResult::Continue)
					},
					Err(_) => Ok(MsgResult::Exit),
				}
			},
			ControlMessage::Write(buf) => if self.tx_mode.may_ever() {
				self.txq.push_back(buf);
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
				Ok(MsgResult::Continue)
			},
		}
	}

	async fn run(mut self) {
		let mut read_deadline = Instant::now() + self.cfg.read_timeout;
		let mut write_deadline = Instant::now() + self.cfg.send_timeout;
		let mut txdummy = Bytes::new();
		let mut rxdummy = BytesMut::new().limit(0);
		let mut has_pending_write = false;
		loop {
			if !self.rx_mode.may_ever() && !self.tx_mode.may_ever() {
				// if the connection can neither read nor write ever again, we only shutdown and then bail out
				self.buf = None;
				select! {
					_ = self.conn.shutdown() => return,
					_ = MAIN_CHANNEL.closed() => return,
				}
			}

			let rxbuf = if self.rx_mode.may() {
				let read_size = self.cfg.read_size;
				self.buf.get_or_insert_with(|| { BytesMut::with_capacity(read_size).limit(read_size) })
			} else {
				&mut rxdummy
			};

			let txbuf = if self.tx_mode.may() {
				match self.txq.front_mut() {
					Some(buf) => {
						if !has_pending_write {
							// this is the first time we're seeing a buffer since the last successful write -> we can advance the write deadline
							write_deadline = Instant::now() + self.cfg.send_timeout;
						}
						has_pending_write = true;
						buf
					},
					None => {
						has_pending_write = false;
						&mut txdummy
					}
				}
			} else {
				&mut txdummy
			};

			let (rx, tx) = self.conn.as_parts_mut();
			pin_mut!(rx);
			pin_mut!(tx);

			select! {
				result = timeout_at(read_deadline.into(), rx.read_buf(rxbuf)), if self.rx_mode.may() => match result {
					Ok(Ok(0)) => {
						debug_assert!(rxbuf.get_ref().has_remaining_mut());
						// at eof
						self.buf = None;
						self.rx_mode = DirectionMode::Closed;
						// we flush our current buffers and then we exit
						self.clean_shutdown_with_msg(None).await;
						return;
					},
					Ok(Ok(n)) => {
						// This is very efficient especially on small reads:
						// instead of resizing the buffer, we keep the existing
						// buffer to avoid fragmentation, at least a little.
						let buf = {
							let inner = rxbuf.get_mut();
							let buf = Bytes::copy_from_slice(&inner[..]);
							inner.truncate(0);
							inner.reserve(self.cfg.read_size);
							drop(inner);
							rxbuf.set_limit(self.cfg.read_size);
							buf
						};
						debug_assert!(buf.len() == n);
						match MAIN_CHANNEL.send(Message::Incoming{
							handle: self.handle.clone(),
							data: buf,
						}).await {
							Ok(_) => (),
							// again, only during shutdown
							Err(_) => return,
						};
						// successful read? -> advance deadline
						read_deadline = Instant::now() + self.cfg.read_timeout;
					},
					Ok(Err(e)) => {
						MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle.clone(), error: Some(Box::new(e))}).await;
						return;
					},
					// read timeout
					Err(_) => {
						let (reply_tx, reply_rx) = oneshot::channel();
						// if it does not really get sent, the reply_rx will
						// complete immediately because the tx got dropped and
						// thus the connection will be closed because of the
						// read timeout. perfect.
						MAIN_CHANNEL.fire_and_forget(Message::ReadTimeout{
							handle: self.handle.clone(),
							keepalive: reply_tx,
						}).await;

						match reply_rx.await {
							Ok(true) => {
								// XXX: this prohibits changing the read timeout from the callback... Might want to return a duration instead.
								read_deadline = Instant::now() + self.cfg.read_timeout;
							},
							Ok(false) | Err(_) => {
								MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
									handle: self.handle.clone(),
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
				},
				result = iodeadline(write_deadline, tx.write_all_buf(txbuf), "write timed out"), if self.tx_mode.may() && txbuf.has_remaining() => match result {
					Ok(()) => {
						// set to false because we cleared the buffer. if this
						// is false, the write deadline will be advanced on
						// the next write.
						// advancing the deadline now would be incorrect
						// because this might be the last thing to write for a
						// long time: it needs to be advanced when the next
						// buffer is selected for writing.
						has_pending_write = false;
						self.txq.pop_front();
					},
					Err(e) => {
						MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle.clone(), error: Some(Box::new(e))}).await;
						return;
					},
				},
				msg = self.rx.recv() => match msg {
					Some(msg) => match self.proc_msg(msg).await {
						Ok(MsgResult::Exit) => return,
						Ok(MsgResult::Continue) => (),
						Err(e) => {
							MAIN_CHANNEL.fire_and_forget(Message::Disconnect{handle: self.handle.clone(), error: Some(Box::new(e))}).await;
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
		tokio::spawn(self.run());
	}
}
