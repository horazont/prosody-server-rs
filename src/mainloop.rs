use mlua::prelude::*;

use std::time::{SystemTime, Instant};

use super::core::{
	Message,
	RUNTIME,
	MAIN_CHANNEL,
};

use super::conn;


fn proc_message<'l>(lua: &'l Lua, msg: Message) -> LuaResult<()> {
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
		Message::TcpAccept{handle, stream, addr} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			let handle = conn::ConnectionHandle::wrap_plain(lua, stream, listeners.clone(), Some(addr))?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onconnect")? {
				Some(func) => {
					func.call::<_, ()>(handle)?;
				},
				None => (),
			};
		},
		Message::TlsAccept{handle, stream, addr} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			let handle = conn::ConnectionHandle::wrap_tls_server(lua, stream, listeners.clone(), Some(addr))?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onstarttls")? {
				Some(func) => {
					func.call::<_, ()>((handle, LuaValue::Nil))?;
				},
				None => (),
			};
		},
		Message::TlsStarted{handle} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			{
				let mut handle = handle.borrow_mut::<conn::ConnectionHandle>()?;
				handle.confirm_starttls();
			}
			let listeners = handle.get_user_value::<LuaTable>()?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onstarttls")? {
				Some(func) => {
					func.call::<_, ()>((handle, LuaValue::Nil))?;
				},
				None => (),
			};
		},
		Message::Incoming{handle, data} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onincoming")? {
				Some(func) => {
					func.call::<_, ()>((handle, lua.create_string(&data)?))?;
				},
				None => (),
			};
		},
		Message::ReadClosed{handle} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			match listeners.get::<&'static str, Option<LuaFunction>>("ondisconnect")? {
				Some(func) => {
					func.call::<_, ()>(handle)?;
				},
				None => (),
			};
		},
		Message::Disconnect{handle, error} => {
			let handle = lua.registry_value::<LuaAnyUserData>(&*handle)?;
			let listeners = handle.get_user_value::<LuaTable>()?;
			let error = error.map(|x| { format!("{}", x)});
			match listeners.get::<&'static str, Option<LuaFunction>>("ondisconnect")? {
				Some(func) => {
					func.call::<_, ()>((handle, error))?;
				},
				None => (),
			};
		},
	};
	Ok(())
}

pub(crate) fn mainloop<'l>(lua: &'l Lua, _: ()) -> LuaResult<()> {
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
	lua.scope(|scope| {
		let ropt = RUNTIME.read().unwrap();
		let r = ropt.as_ref().unwrap();
		let mut rx = MAIN_CHANNEL.lock_rx_lua()?;
		let _guard = r.enter();
		r.block_on(async move {
			loop {
				let msg = match rx.recv().await {
					Some(v) => v,
					None => break,
				};
				match proc_message(lua, msg) {
					Ok(_) => (),
					Err(e) => {
						eprintln!("failed to process event loop message: {}", e)
					},
				}
				// TODO: do this only every N seconds or so
				lua.expire_registry_values();
			};
			Ok(())
		})
	})
}

