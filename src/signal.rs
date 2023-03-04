/*!
# POSIX signal handlers
*/
use mlua::prelude::*;

use std::os::raw::c_int;

use tokio::select;
use tokio::signal::unix::{signal, Signal, SignalKind};

use crate::core::{LuaRegistryHandle, Message, Spawn, MAIN_CHANNEL};
use crate::{prosody_log_g, with_runtime_lua};

struct SignalWorker {
	signal: Signal,
	handle: LuaRegistryHandle,
}

impl SignalWorker {
	async fn run(mut self) {
		loop {
			select! {
				_ = MAIN_CHANNEL.closed() => return,
				sig = self.signal.recv() => match sig {
					Some(_) => {
						match MAIN_CHANNEL.send(Message::Signal{handle: self.handle.clone()}).await {
							Ok(_) => (),
							Err(_) => return,
						}
					},
					None => return,
				},
			}
		}
	}
}

impl Spawn for SignalWorker {
	fn spawn(self) {
		tokio::spawn(self.run());
	}
}

/// CAVEAT: The signal handling stuff used by tokio has the issue that it does keep the old installed signal handler and invokes it after its own signal handler. That means that we cannot overwrite the SIGINT handler installed by lua just like that. That needs fixing later on.
pub(crate) fn hook_signal<'l>(
	lua: &'l Lua,
	(kind_raw, callback): (c_int, LuaFunction),
) -> LuaResult<Result<bool, String>> {
	let kind = match kind_raw {
		14 => SignalKind::alarm(),
		1 => SignalKind::hangup(),
		2 => SignalKind::interrupt(),
		3 => SignalKind::quit(),
		15 => SignalKind::terminate(),
		10 => SignalKind::user_defined1(),
		12 => SignalKind::user_defined2(),
		other => return Ok(Err(format!("unknown or unsupported signal: {}", other))),
	};
	let handle = lua.create_registry_value(callback)?.into();
	with_runtime_lua! {
		let stream = signal(kind)?;
		SignalWorker{
			handle,
			signal: stream,
		}.spawn();
		()
	}
	prosody_log_g!(lua, "debug", "registered signal handler for %s", kind_raw);
	Ok(Ok(true))
}
