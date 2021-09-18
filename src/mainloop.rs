/*!
# Actual mainloop as invoked from Prosody on startup
*/
use mlua::prelude::*;

use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, Instant};

use lazy_static::lazy_static;

use tokio::select;

use super::core::{
	Message,
	RUNTIME,
	MAIN_CHANNEL,
	GC_FLAG,
	WAKEUP,
	call_listener,
	may_call_listener,
};
use crate::stream;
use crate::config::CONFIG;


lazy_static! {
	static ref SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);
	// we do not use a handle here
	pub(crate) static ref LOG_FUNCTION: RwLock<Option<LuaRegistryKey>> = RwLock::new(None);
}

macro_rules! prosody_log {
	($log_fn:expr, $level:expr, $($argv:expr),+) => {
		{
			let args = ($level, $($argv),+);
			#[cfg(feature = "prosody-log")]
			{
				match $log_fn {
					Some(ref log) => {
						log.call::<_, ()>(args)?
					},
					None => (),
				}
			}
			#[cfg(not(feature = "prosody-log"))]
			{
				// to avoid "unused value" warnings
				let _ = args;
				let _ = $log_fn;
			}
		}
	}
}

/**
Log a message via prosody.

This macro is a no-op if the crate is built without the `prosody-log` feature
(enabled by default) or if no logging function has been set at startup (done
by default by the enclosed `server_rust.lua`).

Otherwise, it dereferences the registry key under which the logging function
was saved and attempts to log a message.

Usage:

```ignore
// let lua: &Lua = ...
prosody_log_g!(lua, "debug", "Hello World from %s", "someone");
```

*Note:* The message is string-interpolated by prosody according to its rules.
It is preferable to rely on *that* string interpolation instead of using
`format!`, because it integrates more smoothly with advanced logging sinks
for Prosody.

The downside is that all arguments to this macro need to be ToLua.
*/
#[macro_export]
macro_rules! prosody_log_g {
	($lua:expr, $level:expr, $($argv:expr),+) => {
		{
			#[cfg(feature = "prosody-log")]
			{
				let logfn = crate::mainloop::LOG_FUNCTION.read().unwrap();
				if let Some(logfn) = logfn.as_ref() {
					let logfn = $lua.registry_value::<mlua::Function>(logfn).unwrap();
					logfn.call::<_, ()>(($level, $($argv),+)).unwrap();
				}
			}
			#[cfg(not(feature = "prosody-log"))]
			{
				let _ = ($lua, $level, $($argv),+);
			}
		}
	}
}

#[allow(unused_macros)]
macro_rules! if_log {
	($log_fn:expr => $block:block) => {
		#[cfg(feature = "prosody-log")]
		{
			if $log_fn.is_some() $block
		}
	}
}

#[must_use]
#[inline]
fn check_transition<T>(r: Result<T, stream::StateTransitionError>) -> LuaResult<T> {
	match r {
		Ok(v) => Ok(v),
		Err(e) => Err(LuaError::ExternalError(Arc::new(e))),
	}
}

#[must_use]
#[inline]
fn call_connect<'l>(listeners: &'l LuaTable<'l>, handle: LuaAnyUserData<'l>) -> LuaResult<()> {
	may_call_listener(listeners, "onconnect", handle)
}

#[must_use]
#[inline]
fn call_tls_confirm<'l>(listeners: &'l LuaTable<'l>, handle: LuaAnyUserData<'l>) -> LuaResult<()> {
	may_call_listener(listeners, "onstatus", (handle, "ssl-handshake-complete"))
}

#[must_use]
#[inline]
fn call_starttls<'l>(listeners: &'l LuaTable<'l>, handle: LuaAnyUserData<'l>) -> LuaResult<()> {
	// TODO: proper context
	may_call_listener(listeners, "onstarttls", (handle, LuaValue::Nil))
}

#[must_use]
#[inline]
fn call_disconnect<'l>(listeners: &'l LuaTable<'l>, handle: LuaAnyUserData<'l>, err: Option<String>) -> LuaResult<()> {
	let err = err.unwrap_or_else(|| { "closed".into() });
	may_call_listener(listeners, "ondisconnect", (handle, err))
}

fn proc_message<'l>(lua: &'l Lua, log_fn: Option<&'l LuaFunction>, msg: Message) -> LuaResult<()> {
	match msg {
		Message::TimerElapsed{handle, timestamp, reply} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let func = handle.get_user_value::<LuaFunction>()?;
			match func.call::<_, Option<f64>>((timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs_f64(), handle))? {
				Some(v) => {
					let _ = reply.send(Instant::now() + std::time::Duration::from_secs_f64(v));
				},
				None => (),
			};
		},
		Message::Connect{handle} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			let should_call = {
				let mut handle = handle.borrow_mut::<stream::StreamHandle>()?;
				check_transition(handle.state_mut().connect())?
			};
			if should_call {
				call_connect(&listeners, handle)?;
			}
		},
		Message::TcpAccept{handle, stream, addr} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			let cfg = CONFIG.read().unwrap().stream;
			let handle = stream::StreamHandle::wrap_plain(lua, stream, listeners.clone(), Some(addr), cfg)?;
			call_connect(&listeners, handle)?;
		},
		Message::TlsAccept{handle, stream, addr, verify} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			let cfg = CONFIG.read().unwrap().stream;
			let handle = stream::StreamHandle::wrap_tls_server(lua, stream, listeners.clone(), Some(addr), verify, cfg)?;
			call_starttls(&listeners, handle.clone())?;
			call_tls_confirm(&listeners, handle.clone())?;
			call_connect(&listeners, handle.clone())?;
		},
		Message::TlsStarted{handle, verify} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			let should_call_connect = {
				let mut handle = handle.borrow_mut::<stream::StreamHandle>()?;
				check_transition(handle.state_mut().confirm_tls(verify))?
			};
			call_tls_confirm(&listeners, handle.clone())?;
			if should_call_connect {
				call_connect(&listeners, handle.clone())?;
			}
		},
		Message::Incoming{handle, data} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			may_call_listener(&listeners, "onincoming", (handle, lua.create_string(&data)?))?;
		},
		Message::ReadTimeout{handle, keepalive} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			match call_listener::<_, bool>(&listeners, "onreadtimeout", ()) {
				Err(e) => e.lua_error()?,
				// not using let _ = here to explicitly only ignore a
				// Result<> type, not a Future
				Ok(should_keepalive) => match keepalive.send(should_keepalive) {
					Ok(_) | Err(_) => (),
				},
			}
		},
		Message::ReadClosed{handle} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			let should_call = {
				let mut handle = handle.borrow_mut::<stream::StreamHandle>()?;
				check_transition(handle.state_mut().disconnect())?
			};
			if should_call {
				call_disconnect(&listeners, handle, None)?;
			}
		},
		Message::Disconnect{handle, error} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = stream::get_listeners(&handle)?;
			let should_call = {
				let mut handle = handle.borrow_mut::<stream::StreamHandle>()?;
				check_transition(handle.state_mut().disconnect())?
			};
			if should_call {
				let error = error.map(|x| { x.to_string() });
				call_disconnect(&listeners, handle, error)?;
			}
		},
		Message::Signal{handle} => {
			let func = lua.registry_value::<LuaFunction>(&*handle)?;
			func.call::<_, ()>(())?;
		},
		Message::Readable{handle, confirm} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			may_call_listener(&listeners, "onreadable", handle)?;
			// we can just let confirm drop, that's good enough
			drop(confirm);
		},
		Message::Writable{handle, confirm} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			may_call_listener(&listeners, "onwritable", handle)?;
			// we can just let confirm drop, that's good enough
			drop(confirm);
		},
		#[cfg(feature = "prosody-log")]
		Message::Log{level, message, error} => {
			match error {
				Some(error) => prosody_log!(log_fn, level, "%s (caused by %s)", message, error.to_string()),
				None => prosody_log!(log_fn, level, "%s", message),
			}
		},
	};
	Ok(())
}

pub(crate) fn shutdown<'l>(_lua: &'l Lua, _: ()) -> LuaResult<()> {
	// we mustn't pass through the event queue here, because that might be full and we cannot block on it.
	SHUTDOWN_FLAG.store(true, Ordering::SeqCst);
	WAKEUP.notify_one();
	Ok(())
}

pub(crate) fn set_log_function<'l>(lua: &'l Lua, f: Option<LuaFunction>) -> LuaResult<()> {
	#[cfg(feature = "prosody-log")]
	{
		let mut log_function = LOG_FUNCTION.write().unwrap();
		match log_function.take() {
			None => (),
			Some(_) => GC_FLAG.store(true, Ordering::Relaxed),
		}
		*log_function = Some(lua.create_registry_value(f)?);
	}
	#[cfg(not(feature = "prosody-log"))]
	{
		let _ = lua;
		if let Some(f) = f {
			f.call::<_, ()>(("warn", "Logging requested, but disabled at compile time. No further log messages will be emitted from the network backend!"))?;
		}
	}
	prosody_log_g!(lua, "debug", "Network backend logging enabled.");
	Ok(())
}

pub(crate) fn mainloop<'l>(lua: &'l Lua, _: ()) -> LuaResult<String> {
	/* what is the overall strategy here?

	- We want to make use of concurrency because rust gives us that safely without much cost
	- We want to keep the lua code single threaded because it's easier to reason about it that way

	for this to work, we need to split sockets in two parts (kinda like what I did in the metric relay I guess):

	- The lua part, which also keeps track of the lua-side callbacks. It has a mpsc::Receiver for stuff coming from the network and maybe an mpsc::Sender for stuff going *to* the network.

	- The tokio part, which does the actual work, which may again be separated in sending and receiving tasks. It has the corresponding mpsc::Sender/mpsc::Receiver endpoints to send/take messages to/from lua.

	There are three issues to solve:

	1. How to address the callbacks if we don't have a handle on the socket anymore by the time this function is called?

		- We could store each socket in the registry and hand a RegistryKey to the tokio side and have that included in the message; then tokio can attach the RegistryKey to the message from tokio to lua.

			- Need to take care of dropping the entries from the registry when the socket is gone.

	2. When to create the mpsc pairs and how to store them in the lua side socket?

		- We can live with a single mpsc::Sender/mpsc::Receiver pair for sending data *to* lua, but we need a separate mpsc::Receiver for each socket to distribute work without parallelising work on an individual socket

		- We might need a parallelizer task which takes stuff from lua and fans out to the tokio sockets, though that would be rather inefficient.

			- To avoid the parallelizer, we have to create the mpsc pair for sending to tokio at socket creation time, which means we need to put it somewhere (spawn the socket task(s) even?)

	3. A serializer is needed close to the lua side, because the lua side cannot poll multiple queues at the same time. We may need to spawn that one when we enter the loop.

	This boils down to global state, which kinda makes sense.

	The following global things are needed:

	1. The runtime: to spawn tasks when sockets get created.
	2. The synchronous mpsc::Receiver (plus a sender zygote): to allow spawned tasks to send stuff to lua.
	*/
	let ropt = RUNTIME.read().unwrap();
	let r = ropt.as_ref().unwrap();
	let mut rx = MAIN_CHANNEL.lock_rx_lua()?;
	let _guard = r.enter();
	r.block_on(async move {
		let log_fn = {
			let log_fn = LOG_FUNCTION.read().unwrap();
			match &*log_fn {
				Some(v) => Some(lua.registry_value::<LuaFunction>(v)?),
				None => None,
			}
		};
		prosody_log!(log_fn, "debug", "entered rust event loop");
		loop {
			select! {
				msg = rx.recv() => match msg {
					Some(msg) => match proc_message(lua, log_fn.as_ref(), msg) {
						Ok(()) => (),
						Err(e) => prosody_log!(log_fn, "error", "failed to process event loop message: %s", e.to_string()),
					},
					// this is impossible because one tx of the main channel is held in some arc at global scope
					None => unreachable!(),
				},
				// iterate the loop once to trigger GC if necessary
				_ = WAKEUP.notified() => (),
			}
			if let Ok(_) = SHUTDOWN_FLAG.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst) {
				break
			}
			if let Ok(_) = GC_FLAG.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst) {
				lua.expire_registry_values();
			}
		};
		Ok("quitting".into())
	})
}

