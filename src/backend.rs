use mlua::prelude::*;

use std::ops::{Deref, Drop};
use std::sync::{Arc, RwLock, RwLockReadGuard, Mutex, MutexGuard};
use std::marker::PhantomData;

use lazy_static::lazy_static;

use tokio::select;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use tokio_rustls::rustls;

enum Callback {
	Error,
	Attach,
	Detach,
	Incoming,
	ReadTimeout,
	Disconnect,
	Drain,
	StartTls,
	Status,
	Connect,
}

#[derive(Debug)]
enum LuaMessage {
	Println(String),
	CallString(Arc<LuaRegistryKey>, &'static str, String),

	// Timer elapsed, either drop the sender or return the time after which the next invocation should happen
	TimerElapsed(Arc<LuaRegistryKey>, Option<Arc<LuaRegistryKey>>, oneshot::Sender<std::time::Duration>),

	TcpAccept{key: Arc<LuaRegistryKey>, stream: tokio::net::TcpStream, addr: std::net::SocketAddr},
	TlsAccept{key: Arc<LuaRegistryKey>, stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, addr: std::net::SocketAddr},
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
	static ref runtime: RwLock<Option<Runtime>> = RwLock::new(Some(Builder::new_current_thread().enable_all().build().unwrap()));
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

pub(crate) struct TimerLua {
	guard: oneshot::Sender<()>,
}

impl LuaUserData for TimerLua {}

impl TimerLua {
	fn new<'lua>(lua: &'lua Lua, timeout: std::time::Duration, func: LuaFunction, param: Option<LuaValue>) -> LuaResult<LuaAnyUserData<'lua>> {
		let (local_guard, remote_guard) = oneshot::channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{
			guard: local_guard,
		})?;
		let func = lua.create_registry_value(func)?;
		let param = match param {
			Some(v) => Some(Arc::new(lua.create_registry_value(v)?)),
			None => None,
		};

		let global_tx = main_channel.tx.clone();
		TimerWorker{
			global_tx,
			guard: remote_guard,
			func: Arc::new(func),
			param,
		}.spawn(timeout);
		Ok(v)
	}
}

struct TimerWorker {
	global_tx: mpsc::Sender<LuaMessage>,
	guard: oneshot::Receiver<()>,
	func: Arc<LuaRegistryKey>,
	param: Option<Arc<LuaRegistryKey>>,
}

impl TimerWorker {
	fn spawn(mut self, timeout: std::time::Duration) {
		tokio::spawn(async move { self.run(timeout).await });
	}

	async fn run(&mut self, mut timeout: std::time::Duration) {
		loop {
			select! {
				_ = tokio::time::sleep(timeout) => {
					let (reply_tx, reply_rx) = oneshot::channel();
					match self.global_tx.send(LuaMessage::TimerElapsed(self.func.clone(), self.param.clone(), reply_tx)).await {
						Ok(_) => (),
						Err(_) => break,
					};
					match reply_rx.await {
						Ok(v) => {
							timeout = v;
							continue;
						},
						// reply channel dropped a.k.a. "this callback doesn't want us called again"-
						Err(_) => break,
					};
				},
				_ = &mut self.guard => {
					// main value dropped or requested deregistration, exit.
					break
				},
			}
		}
	}
}

pub(crate) fn add_task<'l>(lua: &'l Lua, (timeout, func, param): (f64, LuaFunction, Option<LuaValue>)) -> LuaResult<LuaAnyUserData<'l>> {
	let timeout = std::time::Duration::from_secs_f64(timeout);
	let guard = runtime.read().unwrap();
	let rt = get_runtime(&guard)?;
	let rt_guard = rt.enter();
	let v = TimerLua::new(lua, timeout, func, param)?;
	Ok(v)
}

struct TcpListenerLua {
	tx: mpsc::UnboundedSender<()>,
	// cached for the lua
	sockaddr: String,
	sockport: u16,
}

impl TcpListenerLua {
	fn new<'l>(lua: &'l Lua, sock: tokio::net::TcpListener, listeners: LuaTable, tls_config: Option<Arc<rustls::ServerConfig>>) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = sock.local_addr()?;

		let (tx, rx) = mpsc::unbounded_channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{
			tx,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		v.set_user_value(listeners)?;
		let key = lua.create_registry_value(v.clone())?;

		let global_tx = main_channel.tx.clone();
		TcpListenerWorker{
			rx,
			global_tx,
			sock,
			tls_config: tls_config.and_then(|x| { Some(x.into()) }),
			key: Arc::new(key),
		}.spawn();
		Ok(v)
	}
}

impl LuaUserData for TcpListenerLua {
}

struct StartTlsWorker {
	global_tx: mpsc::Sender<LuaMessage>,
	accept: tokio_rustls::Accept<tokio::net::TcpStream>,
	addr: std::net::SocketAddr,
	key: Arc<LuaRegistryKey>,
}

impl StartTlsWorker {
	fn spawn(mut self) {
		tokio::spawn(async move { self.run().await });
	}

	async fn run(mut self) {
		let stream = match self.accept.await {
			Ok(v) => v,
			Err(e) => {
				eprintln!("failed to start TLS on TCP stream: {}", e);
				return
			},
		};
		match self.global_tx.send(LuaMessage::TlsAccept{key: self.key, stream, addr: self.addr}).await {
			Ok(_) => (),
			// other side got dropped somehow, exit.
			Err(_) => (),
		}
	}
}

struct TcpListenerWorker {
	rx: mpsc::UnboundedReceiver<()>,
	global_tx: mpsc::Sender<LuaMessage>,
	sock: tokio::net::TcpListener,
	tls_config: Option<tokio_rustls::TlsAcceptor>,
	key: Arc<LuaRegistryKey>,
}

impl TcpListenerWorker {
	fn spawn(mut self) {
		tokio::spawn(async move { self.run().await });
	}

	async fn run(&mut self) {
		loop {
			select! {
				_ = self.rx.recv() => {
					todo!()
				},
				result = self.sock.accept() => match result {
					Ok((stream, addr)) => {
						if let Some(acceptor) = self.tls_config.as_ref() {
							let mut buf = [0u8; 1];
							stream.peek(&mut buf[..]).await.unwrap();
							if buf[0] == 0x16 {
								StartTlsWorker{
									global_tx: self.global_tx.clone(),
									accept: acceptor.accept(stream),
									key: self.key.clone(),
									addr,
								}.spawn();
								continue
							}
						};
						match self.global_tx.send(LuaMessage::TcpAccept{key: self.key.clone(), stream, addr}).await {
							Ok(_) => (),
							// other side got dropped somehow, exit.
							Err(_) => break,
						}

					},
					Err(e) => {
						eprintln!("failed to accept a socket from the listener: {}. I think I need to sleep on that one.", e);
						tokio::time::sleep(std::time::Duration::new(5, 0)).await;
					},
				},
			}
		}
	}
}

pub(crate) fn listen<'l>(lua: &'l Lua, (addr, port, listeners, _config): (String, u16, LuaTable, Option<LuaTable>)) -> LuaResult<LuaAnyUserData<'l>> {
	let addr = addr.parse::<std::net::IpAddr>()?;
	let addr = std::net::SocketAddr::new(addr, port);
	let sock = std::net::TcpListener::bind(addr)?;
	sock.set_nonblocking(true)?;
	let guard = runtime.read().unwrap();
	let rt = get_runtime(&guard)?;
	let rt_guard = rt.enter();
	let sock = tokio::net::TcpListener::from_std(sock)?;
	let mut tls_config = rustls::ServerConfig::new(Arc::new(rustls::NoClientAuth));
	let certs = rustls::internal::pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open("./localhost.crt")?)).unwrap();
	let key = rustls::internal::pemfile::rsa_private_keys(&mut  std::io::BufReader::new(std::fs::File::open("./localhost.key")?)).unwrap().pop().unwrap();
	tls_config.set_single_cert(certs, key);
	let tls_config = Arc::new(tls_config);
	TcpListenerLua::new(lua, sock, listeners, Some(tls_config))
}

struct TcpStreamLua<T> {
	tx: mpsc::UnboundedSender<()>,
	// cached for the lua
	sockaddr: String,
	sockport: u16,
	_marker: PhantomData<*const T>,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> TcpStreamLua<T> {
	fn new<'l>(lua: &'l Lua, stream: T, listeners: LuaTable, addr: std::net::SocketAddr) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v: LuaAnyUserData = lua.create_userdata(Self{
			tx,
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
			_marker: PhantomData,
		})?;
		v.set_user_value(listeners)?;
		let key = lua.create_registry_value(v.clone())?;

		let global_tx = main_channel.tx.clone();
		TcpStreamWorker{
			rx,
			global_tx,
			sock: stream,
			key: Arc::new(key),
		}.spawn();
		Ok(v)
	}
}

impl<T> LuaUserData for TcpStreamLua<T> {}

struct TcpStreamWorker<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
	rx: mpsc::UnboundedReceiver<()>,
	global_tx: mpsc::Sender<LuaMessage>,
	sock: T,
	key: Arc<LuaRegistryKey>,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> TcpStreamWorker<T> {
	fn spawn(mut self) {
		tokio::spawn(async move { self.run().await });
	}

	async fn run(&mut self) {
		// do nothing, drop it
	}
}

fn proc_message<'l>(lua: &'l Lua, msg: LuaMessage) -> LuaResult<()> {
	match msg {
		LuaMessage::CallString(key, name, value) => {
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
		LuaMessage::TimerElapsed(func, param, reply) => {
			let func = lua.registry_value::<LuaFunction>(&*func)?;
			let param = match param {
				Some(key) => Some(lua.registry_value::<LuaValue>(&*key)?),
				None => None,
			};
			// TODO: we need to include the timer handle here
			match func.call::<_, Option<f64>>((LuaValue::Nil, LuaValue::Nil, param))? {
				Some(v) => {
					let _ = reply.send(std::time::Duration::from_secs_f64(v));
				},
				None => (),
			};
		},
		LuaMessage::TcpAccept{key, stream, addr} => {
			let v = lua.registry_value::<LuaAnyUserData>(&*key)?;
			let listeners = v.get_user_value::<LuaTable>()?;
			println!("new connection from {}", addr);
			let conn = TcpStreamLua::new(lua, stream, listeners.clone(), addr)?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onconnect")? {
				Some(func) => {
					func.call::<_, ()>((conn))?;
				},
				None => (),
			};
		},
		LuaMessage::TlsAccept{key, stream, addr} => {
			let v = lua.registry_value::<LuaAnyUserData>(&*key)?;
			let listeners = v.get_user_value::<LuaTable>()?;
			println!("new TLS connection from {}", addr);
			let conn = TcpStreamLua::new(lua, stream, listeners.clone(), addr)?;
			match listeners.get::<&'static str, Option<LuaFunction>>("onstarttls")? {
				Some(func) => {
					func.call::<_, ()>((conn, LuaValue::Nil))?;
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
