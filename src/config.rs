use mlua::prelude::*;

use std::sync::RwLock;
use std::time::Duration;

use lazy_static::lazy_static;

use crate::{strerror_ok, prosody_log_g};
use crate::conversion::{
	to_duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamConfig {
	pub read_timeout: Duration,
	pub send_timeout: Duration,
	pub read_size: usize,
	pub ssl_handshake_timeout: Duration,
}

impl Default for StreamConfig {
	fn default() -> Self {
		// these defaults are based on today's server_epoll
		Self{
			read_timeout: Duration::new(14 * 60, 0),
			send_timeout: Duration::new(180, 0),
			read_size: 8192,
			// note: using a larger value than epoll here because we don't timeout the individual steps, only the end result
			ssl_handshake_timeout: Duration::new(120, 0),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServerConfig {
	pub accept_retry_interval: Duration,
}

impl Default for ServerConfig {
	fn default() -> Self {
		// these defaults are based on today's server_epoll
		Self{
			accept_retry_interval: Duration::new(10, 0),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientConfig {
	pub connect_timeout: Duration,
}

impl Default for ClientConfig {
	fn default() -> Self {
		// these defaults are based on today's server_epoll
		Self{
			connect_timeout: Duration::new(20, 0),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoopConfig {
}

impl Default for LoopConfig {
	fn default() -> Self {
		Self{}
	}
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Config {
	pub stream: StreamConfig,
	pub server: ServerConfig,
	pub client: ClientConfig,
	pub mainloop: LoopConfig,
}

impl Config {
	pub(crate) fn update<'l>(&mut self, lua: &'l Lua, options: LuaTable) -> LuaResult<Result<bool, String>> {
		for kv in options.pairs::<LuaValue, LuaValue>() {
			let (k, v) = kv?;
			let k = match k {
				LuaValue::String(s) => s,
				_ => continue,
			};
			match k.as_bytes() {
				b"read_timeout" => self.stream.read_timeout = strerror_ok!(to_duration(v)),
				b"send_timeout" => self.stream.send_timeout = strerror_ok!(to_duration(v)),
				b"read_size" => self.stream.read_size = strerror_ok!(usize::from_lua(v, lua)),
				b"ssl_handshake_timeout" => self.stream.ssl_handshake_timeout = strerror_ok!(to_duration(v)),
				b"accept_retry_interval" => self.server.accept_retry_interval = strerror_ok!(to_duration(v)),
				b"connect_timeout" => self.client.connect_timeout = strerror_ok!(to_duration(v)),
				_ => (),
			}
		}
		Ok(Ok(true))
	}
}

lazy_static! {
	pub(crate) static ref CONFIG: RwLock<Config> = RwLock::new(Config::default());
}

pub(crate) fn reconfigure<'l>(lua: &'l Lua, options: LuaTable) -> LuaResult<Result<bool, String>> {
	let mut new_config = Config::default();
	strerror_ok!(new_config.update(lua, options)?);
	let mut active_config = CONFIG.write().unwrap();
	*active_config = new_config;
	prosody_log_g!(lua, "debug", "Reconfigured: %s", format!("{:?}", *active_config));
	Ok(Ok(true))
}
