use mlua::prelude::*;

use std::error::Error;
use std::net::SocketAddr;
use std::time::{SystemTime, Instant};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};

use bytes::Bytes;

use lazy_static::lazy_static;

use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use tokio_rustls::server::{TlsStream as ServerTlsStream};

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
		handle: Arc<LuaRegistryKey>,
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
		handle: Arc<LuaRegistryKey>,
		/// The newly accepted stream
		stream: TcpStream,
		/// The remote address of the accepted stream
		addr: SocketAddr,
	},

	/// A TLS-encrypted TCP-like connection has been accepted.
	TlsAccept{
		/// The registry key of the (server) handle to which the connection belongs
		handle: Arc<LuaRegistryKey>,
		/// The newly accepted stream
		stream: ServerTlsStream<TcpStream>,
		/// The remote address of the accepted stream
		addr: SocketAddr,
	},

	/// TLS was started on an existing connection
	TlsStarted{
		/// The registry key of the connection handle
		handle: Arc<LuaRegistryKey>,
	},

	Incoming{
		handle: Arc<LuaRegistryKey>,
		data: Bytes,
	},

	ReadClosed{
		handle: Arc<LuaRegistryKey>,
	},

	Connect{
		/// The registry key of the connection handle
		handle: Arc<LuaRegistryKey>,
	},

	Disconnect{
		/// The registry key of the connection handle
		handle: Arc<LuaRegistryKey>,
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
			Err(_) => Err(LuaError::RuntimeError("something has paniced before and accessing the global receiver is unsafe now".into())),
		}
	}

	pub(crate) fn clone_tx(&self) -> mpsc::Sender<T> {
		self.tx.clone()
	}
}

lazy_static! {
	#[doc(hidden)]
	pub(crate) static ref RUNTIME: RwLock<Option<Runtime>> = RwLock::new(Some(Builder::new_multi_thread().enable_all().build().unwrap()));
	#[doc(hidden)]
	pub(crate) static ref MAIN_CHANNEL: MpscChannel<Message> = MpscChannel::new(1024);
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
