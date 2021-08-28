/**
# Sockets for stream connections

Sockets for stream connections are generally TCP sockets.
*/
use mlua::prelude::*;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use log::{warn, error};

use bytes::{Bytes, BytesMut, BufMut, buf::Limit};

use tokio::select;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream};
use tokio::sync::mpsc;

use tokio_rustls::{TlsAcceptor, server};

use pin_project_lite::pin_project;

use crate::core::{MAIN_CHANNEL, Message, Spawn};

/**
Describe which TLS actions are currently possible on a socket.

This enum is used and cached on the lua side to know which operations are possible without having to call into the worker thread for details.
*/
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

enum ControlMessage {
	Close,
	Write(Bytes),
}

pub(crate) struct ConnectionHandle {
	tx: mpsc::UnboundedSender<ControlMessage>,
	tls_state: CachedTlsState,
	sockaddr: String,
	sockport: u16,
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
	pub(crate) fn wrap_plain<'l>(lua: &'l Lua, conn: TcpStream, listeners: LuaTable, addr: Option<SocketAddr>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
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
			conn: ConnectionState::PlainServer{
				sock: conn,
				tls_config: None,
			},
			read_size: 8192,
			handle: Arc::new(key),
		}.spawn();
		Ok(v)
	}
}

pin_project! {
	#[project = ConnectionStateProj]
	enum ConnectionState {
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

impl AsyncRead for ConnectionState {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_read(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for ConnectionState {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_write(cx, buf),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write(cx, buf),
		}
	}

	fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
		let this = self.project();
		match this {
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_write_vectored(cx, bufs),
			ConnectionStateProj::TlsServer{sock} => sock.poll_write_vectored(cx, bufs),
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_flush(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_flush(cx),
		}
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.project();
		match this {
			ConnectionStateProj::PlainServer{sock, ..} => sock.poll_shutdown(cx),
			ConnectionStateProj::TlsServer{sock} => sock.poll_shutdown(cx),
		}
	}

	fn is_write_vectored(&self) -> bool {
		match self {
			Self::PlainServer{sock, ..} => sock.is_write_vectored(),
			Self::TlsServer{sock, ..} => sock.is_write_vectored(),
		}
	}
}

struct ConnectionWorker {
	global_tx: mpsc::Sender<Message>,
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	conn: ConnectionState,
	read_size: usize,
	handle: Arc<LuaRegistryKey>,
}

enum ReadResult {
	Closed,
	Continue,
}

impl ConnectionWorker {
	#[inline]
	async fn proc_read_buffer(&mut self, buf: Bytes) -> Result<ReadResult, ()> {
		if buf.len() == 0 {
			// end of file
			match self.global_tx.send(Message::ReadClosed{handle: self.handle.clone()}).await {
				Ok(_) => Ok(ReadResult::Closed),
				Err(_) => Err(()),
			}
		} else {
			match self.global_tx.send(Message::Incoming{
				handle: self.handle.clone(),
				data: buf,
			}).await {
				Ok(_) => Ok(ReadResult::Continue),
				// again, only during shutdown
				Err(_) => Err(()),
			}
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
		select! {
			_ = self.conn.shutdown() => return,
			_ = self.global_tx.closed() => return,
		}
	}

	async fn run_wclosed(mut self) {
		let mut buf: Option<Limit<BytesMut>> = None;
		loop {
			if buf.is_none() {
				buf = Some(BytesMut::with_capacity(self.read_size).limit(self.read_size))
			}
			select! {
				result = self.conn.read_buf(buf.as_mut().unwrap()) => match result {
					Ok(_) => match self.proc_read_buffer(buf.take().unwrap().into_inner().freeze()).await {
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

	async fn run_rclosed(mut self) {
		loop {
			select! {
				msg = self.rx.recv() => match msg {
					Some(ControlMessage::Close) => {
						return self.run_draining().await;
					},
					Some(ControlMessage::Write(buf)) => match self.proc_write_buffer(buf).await {
						Ok(()) => (),
						Err(()) => return,
					},
					None => return,
				},
				_ = self.global_tx.closed() => return,
			}
		}
	}

	async fn run(mut self) {
		let mut buf: Option<Limit<BytesMut>> = None;
		loop {
			if buf.is_none() {
				buf = Some(BytesMut::with_capacity(self.read_size).limit(self.read_size))
			}
			select! {
				msg = self.rx.recv() => match msg {
					Some(ControlMessage::Close) => return self.run_wclosed().await,
					Some(ControlMessage::Write(buf)) => match self.proc_write_buffer(buf).await {
						Ok(()) => (),
						Err(()) => return,
					},
					None => return,
				},
				result = self.conn.read_buf(buf.as_mut().unwrap()) => match result {
					Ok(_) => match self.proc_read_buffer(buf.take().unwrap().into_inner().freeze()).await {
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
