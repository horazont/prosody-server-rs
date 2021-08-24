use mlua::prelude::*;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

mod backend;

#[mlua::lua_module]
fn librserver(lua: &Lua) -> LuaResult<LuaTable> {
	let exports = lua.create_table()?;

	let server = lua.create_table()?;
	server.set("loop", lua.create_function(backend::mainloop)?)?;
	server.set("test_mkecho", lua.create_function(backend::test_mksender)?)?;
	exports.set("server", server)?;

	exports.set("version", VERSION)?;

	Ok(exports)
}
