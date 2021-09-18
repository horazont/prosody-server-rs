/*!
# Watches on arbitrary file descriptors for arbitrary events
*/
use mlua::prelude::*;

use std::os::unix::io::RawFd;

use tokio::select;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;

use crate::{with_runtime_lua, send_log};
use crate::core::{Message, LuaRegistryHandle, MAIN_CHANNEL, Spawn};


struct WatchHandle {
	guard: Option<oneshot::Sender<()>>,
	fd: RawFd,
}

impl WatchHandle {
	fn new<'l>(lua: &'l Lua, fd: RawFd, interest: Interest, listeners: LuaTable) -> LuaResult<LuaAnyUserData<'l>> {
		let (guard_tx, guard_rx) = oneshot::channel();

		let v = lua.create_userdata(WatchHandle{
			guard: Some(guard_tx),
			fd: fd,
		})?;
		v.set_user_value(listeners)?;
		let handle: LuaRegistryHandle = lua.create_registry_value(v.clone())?.into();

		WatchWorker{
			guard: guard_rx,
			fd: AsyncFd::new(fd)?,
			interest,
			handle,
		}.spawn();
		Ok(v)
	}

	fn empty<'l>(lua: &'l Lua, fd: RawFd) -> LuaResult<LuaAnyUserData<'l>> {
		let v = lua.create_userdata(WatchHandle{
			guard: None,
			fd,
		})?;
		Ok(v)
	}
}

impl LuaUserData for WatchHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method_mut("close", |_, this, _: ()| -> LuaResult<()> {
			match this.guard.take() {
				Some(ch) => {
					let _ = ch.send(());
				},
				None => (),
			};
			Ok(())
		});
	}

	fn add_fields<'lua, F: LuaUserDataFields<'lua, Self>>(fields: &mut F) {
		fields.add_field_method_get("conn", |_, this| -> LuaResult<RawFd> {
			Ok(this.fd)
		});
	}
}

struct WatchWorker {
	guard: oneshot::Receiver<()>,
	fd: AsyncFd<RawFd>,
	interest: Interest,
	handle: LuaRegistryHandle,
}

impl WatchWorker {
	async fn run(mut self) {
		loop {
			select! {
				_ = MAIN_CHANNEL.closed() => return,
				_ = &mut self.guard => return,
				guard = self.fd.readable(), if self.interest.is_readable() => match guard {
					Ok(mut guard) => {
						let (confirm_tx, confirm_rx) = oneshot::channel();
						match MAIN_CHANNEL.send(Message::Readable{
							handle: self.handle.clone(),
							confirm: confirm_tx,
						}).await {
							Ok(()) => (),
							Err(_) => return,
						};
						// result is irrelevant, we only need to block until the confirmation channel is gone
						let _ = confirm_rx.await;
						guard.clear_ready();
					},
					Err(e) => {
						send_log!("warn", "watchfd broke while waiting for read", Some(e));
						return
					},
				},
				guard = self.fd.writable(), if self.interest.is_writable() => match guard {
					Ok(mut guard) => {
						let (confirm_tx, confirm_rx) = oneshot::channel();
						match MAIN_CHANNEL.send(Message::Writable{
							handle: self.handle.clone(),
							confirm: confirm_tx,
						}).await {
							Ok(()) => (),
							Err(_) => return,
						};
						// result is irrelevant, we only need to block until the confirmation channel is gone
						let _ = confirm_rx.await;
						guard.clear_ready();
					},
					Err(e) => {
						send_log!("warn", "watchfd broke while waiting for write", Some(e));
						return
					},
				},
			}
		}
	}
}

impl Spawn for WatchWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}


pub(crate) fn watchfd<'l>(lua: &'l Lua, (fd, readcb, writecb): (RawFd, Option<LuaFunction>, Option<LuaFunction>)) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let listeners = lua.create_table_with_capacity(0, 2)?;
	let interest = match (readcb.is_some(), writecb.is_some()) {
		(false, false) => return Ok(Ok(WatchHandle::empty(lua, fd)?)),
		(true, false) => Interest::READABLE,
		(true, true) => Interest::READABLE.add(Interest::WRITABLE),
		(false, true) => Interest::WRITABLE,
	};
	listeners.set("onreadable", readcb)?;
	listeners.set("onwritable", writecb)?;

	with_runtime_lua! {
		Ok(Ok(WatchHandle::new(lua, fd, interest, listeners)?))
	}
}
