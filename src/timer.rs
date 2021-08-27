/**
# Timers

Provides simple timer functionality. Timers are represented on the Lua side via their [`TimerHandle`] object. This object has `:close()` and `:reschedule(t)` methods which can be used to close the timer or change the time at which it fires next.

On the tokio side, the timer is implemented via the [`TimerWorker`] struct.
*/
use mlua::prelude::*;

use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};

use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;

use super::core::{Message, MAIN_CHANNEL, with_runtime_lua};


/**
Handle on a rust-based timer.

Lua methods offered:

- `:close()`: Asks the timer worker to exit immediately, invalidating the timer handle from future use.
- `:reschedule(t)`: Reschedule the timer to run in `t` seconds, no matter what its current expiration interval is.
*/
struct TimerHandle {
	schedule: Arc<watch::Sender<Instant>>,
	close: Option<oneshot::Sender<()>>,
}

impl LuaUserData for TimerHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method_mut("close", |_, this: &mut Self, _: ()| -> LuaResult<()> {
			// we do not care about the result: either the receiver is gone already (then there's also no task triggering the timer) or the receiver will pick up on the cancellation request
			if let Some(ch) = this.close.take() {
				let _ = ch.send(());
			}
			Ok(())
		});

		methods.add_method("reschedule", |_, this: &Self, t: f64| -> LuaResult<()> {
			// we do not care about the result: either the receiver is gone already (then there's also no task triggering the timer) or it will receive this eventually.
			let _ = this.schedule.send(Instant::now() + Duration::from_secs_f64(t));
			Ok(())
		});
	}
}

impl TimerHandle {
	fn new<'lua>(lua: &'lua Lua, timeout: Duration, func: LuaFunction) -> LuaResult<LuaAnyUserData<'lua>> {
		let (schedule_tx, schedule_rx) = watch::channel(Instant::now() + timeout);
		let (close_tx, close_rx) = oneshot::channel();
		let schedule_tx = Arc::new(schedule_tx);

		let v: LuaAnyUserData = lua.create_userdata(Self{
			schedule: schedule_tx.clone(),
			close: Some(close_tx),
		})?;
		v.set_user_value(func)?;
		let handle = Arc::new(lua.create_registry_value(v.clone())?);

		let global_tx = MAIN_CHANNEL.clone_tx();
		TimerWorker{
			global_tx,
			self_schedule: schedule_tx,
			schedule: schedule_rx,
			close: close_rx,
			handle,
		}.spawn();
		Ok(v)
	}
}

/**
Tokio-side implementation of of a timer.
*/
struct TimerWorker {
	global_tx: mpsc::Sender<Message>,
	self_schedule: Arc<watch::Sender<Instant>>,
	schedule: watch::Receiver<Instant>,
	close: oneshot::Receiver<()>,
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
			let target: Instant = *self.schedule.borrow_and_update();
			let sleeptime = target.saturating_duration_since(now);
			// NOTE: select! is fair in the sense that it'll pick a random one if multiple futures complete. That means that the fact that we saturate the sleeptime to 0 is at most an inefficiency and not an issue with starvation of the cancellation channel.
			select! {
				_ = tokio::time::sleep(sleeptime) => {
					let new_target = match self.elapsed().await {
						Some(v) => v,
						None => return,
					};
					// cannot fail, we hold the receiver
					let _ = self.self_schedule.send(new_target);
				},
				v = self.schedule.changed() => match v {
					// if we got a new target value, we have to reloop
					Ok(_) => continue,
					// unreachable as of the time of writing, but if the sender half had been dropped, we'd want to exit
					Err(_) => return,
				},
				_ = &mut self.close => return,
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
