#![allow(rustdoc::private_intra_doc_links)]
/*!
# Network backend for Prosody

Writen in rust.

## Features

* Multi-threaded network I/O and TLS operations
* Drop-in replacement (given some patches to prosody which will hopefully be
  mainlined)
* Support for direct TLS, STARTTLS and plain TCP connections.
* Support for client and server certificate validation using a standard or
  custom trust store.

## Non-features

* Full compatibility with OpenSSL / LuaSec options

## Architecture

This network backend bases on tokio and uses a multi-threaded runtime. In
order to be safe to use with single-threaded prosody, a message passing
architecture is employed.

Each event source (network socket, timer, signal, watched fd etc.) gets a
worker (which is a tokio task), a handle (lua userdata) and a message queue
which allows the handle to send instructions to the worker.

(In reality, not all primitives have a queue, as not all of them have ways to
instruct the worker.)

The worker holds a strong reference to the handle. This is required because
the handle is where the listeners are attached and the handle needs to be
passed to the listeners on each event. This is achieved using the Lua registry
API exposed by mlua. When the worker exits, that handle is dropped (and a
registry garbage collection is eventually triggered to run in the main loop).

In order to call into lua from the workers, a bounded global message queue
exists. The main loop function polls that message queue and acts on the
messages, generally invoking listeners or transforming passed objects into lua
handles (on tcp accepts).

A very simple and well-documented part of this crate is the [`timer`] module.
The most complex part is the [`stream`] module, which handles TCP stream
connections, including starttls transitions and full-duplex I/O with timeouts.
*/
use mlua::prelude::*;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

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
pub mod ioutil;

/**
Entrypoint for for loading this crate as a Lua module.
*/
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

	// And we do another evil bit… Lua hooks SIGTERM and others... And that's
	// a total buzzkill because the signal handling library used by tokio
	// tries to be smart and will call those signal handlers. They will,
	// however, inject a fault into the lua state, which we really can't have,
	// so we remove those now. Sorry.
	unsafe { nix::sys::signal::signal(
		nix::sys::signal::Signal::SIGTERM,
		nix::sys::signal::SigHandler::SigDfl,
	).unwrap() };
	unsafe { nix::sys::signal::signal(
		nix::sys::signal::Signal::SIGINT,
		nix::sys::signal::SigHandler::SigDfl,
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
