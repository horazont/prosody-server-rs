use mlua::prelude::*;

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
			Err(_) => Err(LuaError::RuntimeError("something has paniced before and accessing the global receiver is unsafe now".into())),
		}
	}

	pub(crate) fn clone_tx(&self) -> mpsc::Sender<T> {
		self.tx.clone()
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
		None => Err(LuaError::RuntimeError("server backend runtime has exited".into())),
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
