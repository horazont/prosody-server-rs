use mlua::prelude::*;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

//mod backend;
mod core;
mod mainloop;
mod timer;

#[mlua::lua_module]
fn librserver(lua: &Lua) -> LuaResult<LuaTable> {
	let exports = lua.create_table()?;

	let server = lua.create_table()?;
	server.set("loop", lua.create_function(mainloop::mainloop)?)?;
	server.set("_add_task", lua.create_function(timer::add_task)?)?;
	/* server.set("test_mkecho", lua.create_function(backend::test_mksender)?)?;
	server.set("listen", lua.create_function(backend::listen)?)?; */
	exports.set("server", server)?;

	exports.set("version", VERSION)?;

	Ok(exports)
}
