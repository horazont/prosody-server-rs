use mlua::prelude::*;

use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};

use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;

use super::core::{Message, MAIN_CHANNEL, with_runtime_lua};


struct TimerHandle {
	schedule: Arc<watch::Sender<Option<Instant>>>,
}

impl LuaUserData for TimerHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("close", |_, this: &Self, _: ()| -> LuaResult<()> {
			// we do not care about the result: either the receiver is gone already (then there's also no task triggering the timer) or the receiver will pick up on the cancellation request
			let _ = this.schedule.send(None);
			Ok(())
		});

		methods.add_method("reschedule", |_, this: &Self, t: f64| -> LuaResult<()> {
			// we do not care about the result: either the receiver is gone already (then there's also no task triggering the timer) or it will receive this eventually.
			let _ = this.schedule.send(Some(Instant::now() + Duration::from_secs_f64(t)));
			Ok(())
		});
	}
}

impl TimerHandle {
	fn new<'lua>(lua: &'lua Lua, timeout: Duration, func: LuaFunction) -> LuaResult<LuaAnyUserData<'lua>> {
		let (schedule_tx, schedule_rx) = watch::channel(Some(Instant::now() + timeout));
		let schedule_tx = Arc::new(schedule_tx);

		let v: LuaAnyUserData = lua.create_userdata(Self{
			schedule: schedule_tx.clone(),
		})?;
		v.set_user_value(func)?;
		let handle = Arc::new(lua.create_registry_value(v.clone())?);

		let global_tx = MAIN_CHANNEL.clone_tx();
		TimerWorker{
			global_tx,
			self_schedule: schedule_tx,
			schedule: schedule_rx,
			handle,
		}.spawn();
		Ok(v)
	}
}

struct TimerWorker {
	global_tx: mpsc::Sender<Message>,
	self_schedule: Arc<watch::Sender<Option<Instant>>>,
	schedule: watch::Receiver<Option<Instant>>,
	handle: Arc<LuaRegistryKey>,
}

impl TimerWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}

	async fn elapsed(&mut self) -> Option<Instant> {
		let (reply_tx, reply_rx) = oneshot::channel();
		let timestamp = SystemTime::now();
		match self.global_tx.send(Message::TimerElapsed{
			handle: self.handle.clone(),
			timestamp,
			reply: reply_tx
		}).await {
			Ok(_) => (),
			Err(_) => return None,
		};
		reply_rx.await.ok()
	}

	async fn run(mut self) {
		loop {
			let now = Instant::now();
			let target: Instant = match *self.schedule.borrow_and_update() {
				Some(v) => v,
				// request to exit
				None => return,
			};
			let sleeptime = target.saturating_duration_since(now);
			// NOTE: select! is fair in the sense that it'll pick a random one if multiple futures complete. That means that the fact that we saturate the sleeptime to 0 is at most an inefficiency and not an issue with starvation of the cancellation channel.
			select! {
				_ = tokio::time::sleep(sleeptime) => {
					let new_target = match self.elapsed().await {
						Some(v) => v,
						None => return,
					};
					if self.schedule.borrow().is_none() {
						// make sure that a concurrent attempt to close the channel always takes precedence
						return
					}
					// cannot fail, we hold the receiver
					let _ = self.self_schedule.send(Some(new_target));
				},
				v = self.schedule.changed() => match v {
					// if we got a new target value, we have to reloop
					Ok(_) => continue,
					// unreachable as of the time of writing, but if the sender half had been dropped, we'd want to exit
					Err(_) => return,
				},
			}
		}
	}
}

pub(crate) fn add_task<'l>(lua: &'l Lua, (timeout, func): (f64, LuaFunction)) -> LuaResult<LuaAnyUserData<'l>> {
	let timeout = std::time::Duration::from_secs_f64(timeout);
	with_runtime_lua(|| {
		let result = TimerHandle::new(lua, timeout, func);
		result
	})
}
