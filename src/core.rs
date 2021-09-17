use mlua::prelude::*;

use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, Drop};
use std::time::{SystemTime, Instant};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;

use lazy_static::lazy_static;

use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};
use tokio::sync;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use tokio_rustls::server::{TlsStream as ServerTlsStream};

use crate::conversion::opaque;
use crate::verify;

/**
# Message / Method Call into Lua

The variants of this enum reflect calls into the Lua code, triggered by the (mainly socket) workers running in the tokio runtime.

See the docs of the individual variants for details.
*/
#[derive(Debug)]
pub(crate) enum Message {
	/// A timer has elapsed.
	TimerElapsed{
		/// The registry key of the timer handle.
		handle: LuaRegistryHandle,
		/// The timestamp at which the timer tripped.
		timestamp: SystemTime,
		/// Return value channel for the interval until the next invocation.
		///
		/// If this channel is dropped without sending a value, the callback will not be invoked again (and the registry keys will be dropped).
		reply: oneshot::Sender<Instant>,
	},

	/// A plain-text TCP-like connection has been accepted.
	TcpAccept{
		/// The registry key of the (server) handle to which the connection belongs
		handle: LuaRegistryHandle,
		/// The newly accepted stream
		stream: TcpStream,
		/// The remote address of the accepted stream
		addr: SocketAddr,
	},

	/// A TLS-encrypted TCP-like connection has been accepted.
	TlsAccept{
		/// The registry key of the (server) handle to which the connection belongs
		handle: LuaRegistryHandle,
		/// The newly accepted stream
		stream: ServerTlsStream<TcpStream>,
		/// The remote address of the accepted stream
		addr: SocketAddr,
		/// Verification information about the new connection
		verify: verify::VerificationRecord,
	},

	/// TLS was started on an existing connection
	TlsStarted{
		/// The registry key of the connection handle
		handle: LuaRegistryHandle,
		/// Verification status
		verify: verify::VerificationRecord,
	},

	Incoming{
		handle: LuaRegistryHandle,
		data: Bytes,
	},

	ReadClosed{
		handle: LuaRegistryHandle,
	},

	ReadTimeout{
		handle: LuaRegistryHandle,

		/// Reply channel to decide what to do with the socket
		///
		/// If the channel is dropped or false is sent, the socket is
		/// disconnected (a Disconnect message is sent appropriately).
		/// Otherwise, the read deadline is advanced and the connection is
		/// given another chance.
		keepalive: oneshot::Sender<bool>,
	},

	Connect{
		/// The registry key of the connection handle
		handle: LuaRegistryHandle,
	},

	Disconnect{
		/// The registry key of the connection handle
		handle: LuaRegistryHandle,
		error: Option<Box<dyn Error + Send + 'static>>,
	},

	/// watchfd notification
	Readable{
		handle: LuaRegistryHandle,
		confirm: oneshot::Sender<()>,
	},

	/// watchfd notification
	Writable{
		handle: LuaRegistryHandle,
		confirm: oneshot::Sender<()>,
	},

	Signal{
		/// The registry key of the function to invoke
		handle: LuaRegistryHandle,
	},

	/// Error which is unrelated to a specific connection, e.g. during an accept()
	#[cfg(feature = "prosody-log")]
	Log{
		level: &'static str,
		message: Cow<'static, str>,
		error: Option<Box<dyn Error + Send + 'static>>,
	},
}

/// Wrapper around an MpscChannel which brokers access to the rx/tx pair
pub(crate) struct MpscChannel<T> {
	rx: Mutex<mpsc::Receiver<T>>,
	tx: mpsc::Sender<T>,
}

impl<T> MpscChannel<T> {
	/// Create a new channel with the given depth
	fn new(depth: usize) -> Self {
		let (tx, rx) = mpsc::channel(depth);
		Self{rx: Mutex::new(rx), tx}
	}

	/// Lock the receiver
	///
	/// If locking fails, a lua error is returned. Locking can only fail if the previous user has paniced .... in which case we're in trouble.
	pub(crate) fn lock_rx_lua(&self) -> LuaResult<MutexGuard<'_, mpsc::Receiver<T>>> {
		match self.rx.lock() {
			Ok(l) => Ok(l),
			Err(_) => Err(opaque("something has paniced before and accessing the global receiver is unsafe now").into()),
		}
	}

	#[inline]
	pub(crate) async fn fire_and_forget(&self, msg: T) {
		let _ = self.tx.send(msg).await;
	}

	#[inline]
	#[must_use]
	pub(crate) async fn send(&self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
		self.tx.send(msg).await
	}

	#[inline]
	pub(crate) async fn closed(&self) -> () {
		self.tx.closed().await
	}
}

static MAIN_CAPACITY: usize = 1024;

lazy_static! {
	#[doc(hidden)]
	pub(crate) static ref RUNTIME: RwLock<Option<Runtime>> = RwLock::new(Some(Builder::new_multi_thread().enable_all().build().unwrap()));
	#[doc(hidden)]
	pub(crate) static ref MAIN_CHANNEL: MpscChannel<Message> = MpscChannel::new(MAIN_CAPACITY);
	pub(crate) static ref WAKEUP: Arc<sync::Notify> = Arc::new(sync::Notify::new());
	#[doc(hidden)]
	pub(crate) static ref GC_FLAG: AtomicBool = AtomicBool::new(false);
}

pub(crate) fn get_runtime<'x>(guard: &'x RwLockReadGuard<'x, Option<Runtime>>) -> LuaResult<&'x Runtime> {
	match guard.as_ref() {
		Some(v) => Ok(v),
		None => Err(opaque("server backend runtime has exited").into()),
	}
}

pub(crate) trait Spawn {
	fn spawn(self);
}

pub(crate) struct WakeupOnDrop();

impl Drop for WakeupOnDrop {
	fn drop(&mut self) {
		WAKEUP.notify_one();
	}
}

pub(crate) struct GcOnDrop(WakeupOnDrop);

impl GcOnDrop {
	fn prepare() -> Self {
		Self(WakeupOnDrop())
	}
}

impl Drop for GcOnDrop {
	fn drop(&mut self) {
		GC_FLAG.store(true, Ordering::SeqCst);
	}
}

pub(crate) struct GcLuaRegistryKey{
	inner: LuaRegistryKey,
	#[allow(dead_code)]
	guard: GcOnDrop,
}

impl From<LuaRegistryKey> for GcLuaRegistryKey {
	fn from(other: LuaRegistryKey) -> Self {
		Self{inner: other, guard: GcOnDrop::prepare()}
	}
}

impl Deref for GcLuaRegistryKey {
	type Target = LuaRegistryKey;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl AsRef<LuaRegistryKey> for GcLuaRegistryKey {
	fn as_ref(&self) -> &LuaRegistryKey {
		&self.inner
	}
}

#[derive(Clone)]
pub(crate) struct LuaRegistryHandle(pub(crate) Arc<GcLuaRegistryKey>);

impl From<LuaRegistryKey> for LuaRegistryHandle {
	fn from(other: LuaRegistryKey) -> Self {
		Self(Arc::new(other.into()))
	}
}

impl Deref for LuaRegistryHandle {
	type Target = LuaRegistryKey;

	fn deref(&self) -> &Self::Target {
		&self.0.inner
	}
}

impl AsRef<LuaRegistryKey> for LuaRegistryHandle {
	fn as_ref(&self) -> &LuaRegistryKey {
		&self.0.inner
	}
}

impl fmt::Debug for LuaRegistryHandle {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(&self.0.inner, f)
	}
}

#[derive(Debug)]
pub(crate) enum ListenerError<'s> {
	LuaError(LuaError),
	NotFound(&'s str),
}

impl<'s> ListenerError<'s> {
	pub(crate) fn lua_error(self) -> LuaResult<()> {
		match self {
			Self::LuaError(e) => Err(e),
			_ => Ok(()),
		}
	}
}

impl<'s> From<LuaError> for ListenerError<'s> {
	fn from(other: LuaError) -> Self {
		Self::LuaError(other)
	}
}

impl<'s> fmt::Display for ListenerError<'s> {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::LuaError(e) => fmt::Display::fmt(e, f),
			Self::NotFound(s) => write!(f, "listener {:?} not set", s),
		}
	}
}

impl<'s> std::error::Error for ListenerError<'s> {}

#[must_use]
pub(crate) fn call_listener<'l, 'n, P: ToLuaMulti<'l>, R: FromLuaMulti<'l>>(listeners: &'l LuaTable<'l>, listener: &'n str, p: P) -> Result<R, ListenerError<'n>> {
	let func = match listeners.get::<_, Option<LuaFunction>>(listener)? {
		Some(func) => func,
		None => return Err(ListenerError::NotFound(listener)),
	};
	Ok(func.call::<_, R>(p)?)
}

#[must_use]
pub(crate) fn may_call_listener<'l, 'n, P: ToLuaMulti<'l>>(listeners: &'l LuaTable<'l>, listener: &'n str, p: P) -> LuaResult<()> {
	match call_listener::<P, ()>(listeners, listener, p) {
		Ok(()) => Ok(()),
		Err(e) => e.lua_error(),
	}
}

#[macro_export]
macro_rules! with_runtime_lua {
	($($b:stmt);*) => {
		{
			let guard = crate::core::RUNTIME.read().unwrap();
			let rt = crate::core::get_runtime(&guard)?;
			let _rt_guard = rt.enter();
			$($b)*
		}
	}
}

#[macro_export]
macro_rules! send_log {
	($level:expr, $msg:literal, $error:expr) => {
		{
			#[cfg(feature = "prosody-log")]
			{
				crate::core::MAIN_CHANNEL.fire_and_forget(crate::core::Message::Log{
					level: $level,
					message: std::borrow::Cow::Borrowed($msg),
					error: $error.map(|x| { Box::new(x) as Box::<dyn std::error::Error + Send + 'static> }),
				}).await;
			}
			#[cfg(not(feature = "prosody-log"))]
			{
				// silenced used value
				let _ = ($level, $msg, $error);
			}
		}
	};
}
