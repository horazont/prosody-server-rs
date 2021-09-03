use mlua::prelude::*;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

//mod backend;
mod conversion;
mod core;
mod mainloop;
mod timer;
mod server;
mod conn;
mod tls;

#[mlua::lua_module]
fn librserver(lua: &Lua) -> LuaResult<LuaTable> {
	let exports = lua.create_table()?;

	let server = lua.create_table()?;
	server.set("loop", lua.create_function(mainloop::mainloop)?)?;
	server.set("_add_task", lua.create_function(timer::add_task)?)?;
	server.set("listen", lua.create_function(server::listen)?)?;
	server.set("addclient", lua.create_function(conn::addclient)?)?;
	server.set("new_tls_config", lua.create_function(tls::new_tls_config)?)?;
	exports.set("server", server)?;

	exports.set("version", VERSION)?;

	Ok(exports)
}
