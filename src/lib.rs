use mlua::prelude::*;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

//mod backend;
mod conversion;
mod core;
mod mainloop;
mod timer;
mod server;
mod stream;
mod tls;
mod signal;
mod fd;
mod verify;
mod cert;
mod config;
mod ioutil;

#[mlua::lua_module]
fn librserver(lua: &Lua) -> LuaResult<LuaTable> {
	// Nothing expects the ~spanish inquisition~ SIGPIPE, so we mask it here.
	// Normally, rust masks SIGPIPE on its own:
	// https://github.com/rust-lang/rust/issues/62569
	// But as its part of the startup code, it doesn't get executed when
	// loading as a library. So we do it here.

	// We don't care about the result, only that it's successful, so the
	// safety concerns do not apply to us.
	unsafe { nix::sys::signal::signal(
		nix::sys::signal::Signal::SIGPIPE,
		nix::sys::signal::SigHandler::SigIgn,
	).unwrap() };

	let exports = lua.create_table()?;

	let server = lua.create_table()?;
	server.set("loop", lua.create_function(mainloop::mainloop)?)?;
	server.set("shutdown", lua.create_function(mainloop::shutdown)?)?;
	server.set("set_log_function", lua.create_function(mainloop::set_log_function)?)?;
	server.set("_add_task", lua.create_function(timer::add_task)?)?;
	server.set("listen", lua.create_function(server::listen)?)?;
	server.set("addclient", lua.create_function(stream::addclient)?)?;
	server.set("wrapclient", lua.create_function(stream::wrapclient)?)?;
	server.set("watchfd", lua.create_function(fd::watchfd)?)?;
	server.set("new_tls_config", lua.create_function(tls::new_tls_config)?)?;
	server.set("hook_signal", lua.create_function(signal::hook_signal)?)?;
	server.set("reconfigure", lua.create_function(config::reconfigure)?)?;
	exports.set("server", server)?;

	exports.set("version", VERSION)?;

	Ok(exports)
}
