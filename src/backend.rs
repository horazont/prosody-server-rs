use mlua::prelude::*;

use std::ops::{Deref, Drop};
use std::sync::{Arc, RwLock, RwLockReadGuard, Mutex, MutexGuard};

use lazy_static::lazy_static;

use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;

#[derive(Debug)]
enum LuaMessage {
	Println(String),
	CallString(Arc<LuaRegistryKey>, &'static str, String),
}

struct MpscPair<T> {
	rx: Mutex<mpsc::Receiver<T>>,
	tx: mpsc::Sender<T>,
}

impl<T> MpscPair<T> {
	fn new(depth: usize) -> Self {
		let (tx, rx) = mpsc::channel(depth);
		Self{rx: Mutex::new(rx), tx}
	}

	fn lock_rx_lua(&self) -> LuaResult<MutexGuard<'_, mpsc::Receiver<T>>> {
		match self.rx.lock() {
			Ok(l) => Ok(l),
			Err(_) => Err(LuaError::RuntimeError("something has paniced before and accessing the global receiver is unsafe now".into())),
		}
	}
}

lazy_static! {
	static ref runtime: RwLock<Option<Runtime>> = RwLock::new(Some(Builder::new_multi_thread().enable_all().build().unwrap()));
	static ref main_channel: MpscPair<LuaMessage> = MpscPair::new(1024);
}

fn get_runtime<'x>(guard: &'x RwLockReadGuard<'x, Option<Runtime>>) -> LuaResult<&'x Runtime> {
	match guard.as_ref() {
		Some(v) => Ok(v),
		None => Err(LuaError::RuntimeError("server backend runtime has exited".into())),
	}
}

pub(crate) struct EchoLua {
	tx: mpsc::UnboundedSender<String>,
}

impl EchoLua {
	fn new<'lua>(lua: &'lua Lua) -> LuaResult<LuaAnyUserData> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{tx})?;
		let key = lua.create_registry_value(v.clone())?;

		let global_tx = main_channel.tx.clone();
		EchoWorker{
			global_tx,
			rx,
			key: Arc::new(key),
		}.spawn();
		Ok(v)
	}
}

impl LuaUserData for EchoLua {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("send", |_, this, msg: String| -> LuaResult<()> {
			match this.tx.send(msg) {
				Ok(_) => Ok(()),
				Err(_) => Err(LuaError::RuntimeError("failed to send through channel".into())),
			}
		});
	}
}

struct EchoWorker {
	rx: mpsc::UnboundedReceiver<String>,
	global_tx: mpsc::Sender<LuaMessage>,
	key: Arc<LuaRegistryKey>,
}

impl EchoWorker {
	fn spawn(mut self) {
		tokio::spawn(async move {
			self.run().await
		});
	}

	async fn run(&mut self) {
		loop {
			let text = match self.rx.recv().await {
				Some(v) => v,
				None => break,
			};
			match self.global_tx.send(LuaMessage::CallString(self.key.clone(), "onreceived", text)).await {
				Ok(_) => (),
				Err(_) => break,
			};
		}
	}
}

pub(crate) fn test_mksender<'l>(lua: &'l Lua, listeners: LuaTable) -> LuaResult<LuaAnyUserData<'l>> {
	let guard = runtime.read().unwrap();
	let rt = get_runtime(&guard)?;
	let rt_guard = rt.enter();
	let v = EchoLua::new(lua)?;
	v.set_user_value(listeners)?;
	Ok(v)
}

/* pub(crate) struct Server<'a> {
	conn: net::TcpListener,
	// cache them to avoid a fallible syscall when lua asks
	sockaddr: String,
	sockport: u16,
}

impl<'a> LuaUserData for Server<'a> {
	fn add_fields<'lua, F: LuaUserDataFields<'lua, Self>>(fields: &mut F) {
		fields.add_field_method_get("sockname", |l: &'lua Lua, this: &Self| -> LuaResult<String> {
			Ok(this.sockaddr)
		});

		fields.add_field_method_get("sockport", |l: &'lua Lua, this: &Self| -> LuaResult<u16> {
			Ok(this.sockport)
		});
	}

	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		// noop
	}
}


pub(crate) fn addserver<'l>(_lua: &'l Lua, (addr, port, listeners, _read_size, _tls_ctx): (String, u16, LuaValue, LuaValue, LuaValue)) -> LuaResult<Server<'l>> {
	let addr = addr.parse::<net::IpAddr>()?;
	let sock = net::TcpListener::bind(net::SocketAddr::new(addr, port))?;

	Ok(Server{
		conn: sock,
		listeners,
		sockaddr: format!("{}", addr),
		sockport: port,
	})
}*/

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
		let ropt = runtime.read().unwrap();
		let r = ropt.as_ref().unwrap();
		let mut rx = main_channel.lock_rx_lua()?;
		let _guard = r.enter();
		r.block_on(async move {
			loop {
				let msg = match rx.recv().await {
					Some(v) => v,
					None => break,
				};
				match msg {
					LuaMessage::CallString(key, name, value) => {
						// TODO: error handling should probably not exit the entire main loop (:
						let v = lua.registry_value::<LuaAnyUserData>(&*key)?;
						let listeners = v.get_user_value::<LuaTable>()?;
						match listeners.get::<&'static str, Option<LuaFunction>>(name)? {
							Some(func) => {
								func.call::<_, ()>((value))?;
							},
							None => (),
						}
					},
					LuaMessage::Println(text) => println!("{}", text),
				};
				// TODO: do this only every N seconds or so
				lua.expire_registry_values();
			};
			Ok(())
		})
	})
}
