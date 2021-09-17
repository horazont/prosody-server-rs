use mlua::prelude::*;

use tokio::select;
use tokio::signal::unix::{signal, Signal, SignalKind};

use crate::{prosody_log_g, with_runtime_lua};
use crate::core::{Message, LuaRegistryHandle, Spawn, MAIN_CHANNEL};


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
		tokio::spawn(async move { self.run().await });
	}
}


/// CAVEAT: The signal handling stuff used by tokio has the issue that it does keep the old installed signal handler and invokes it after its own signal handler. That means that we cannot overwrite the SIGINT handler installed by lua just like that. That needs fixing later on.
pub(crate) fn hook_signal<'l>(lua: &'l Lua, (kind, callback): (LuaString, LuaFunction)) -> LuaResult<Result<bool, String>> {
	let kind = match kind.as_bytes() {
		b"SIGALRM" => SignalKind::alarm(),
		b"SIGHUP" => SignalKind::hangup(),
		b"SIGINT" => SignalKind::interrupt(),
		b"SIGQUIT" => SignalKind::quit(),
		b"SIGTERM" => SignalKind::terminate(),
		b"SIGUSR1" => SignalKind::user_defined1(),
		b"SIGUSR2" => SignalKind::user_defined2(),
		b"SIGWINCH" => SignalKind::window_change(),
		other => match std::str::from_utf8(other) {
			Ok(s) => return Ok(Err(format!("unknown or unsupported signal: {}", s))),
			Err(_) => return Ok(Err(format!("invalid signal name (must be valid UTF-8)"))),
		},
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
