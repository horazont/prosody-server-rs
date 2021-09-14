use mlua::prelude::*;

use std::net::SocketAddr;
use std::os::unix::io::{RawFd, FromRawFd};
use std::sync::Arc;

use tokio::net::TcpStream;

use nix::{
	fcntl::FcntlArg,
	fcntl::fcntl,
};

use crate::{
	strerror_ok,
	with_runtime_lua,
};
use crate::core::{
	may_call_listener,
};
use crate::config::CONFIG;
use crate::conversion;
use crate::tls;

use super::state::{
	PreTlsConfig,
	StateTransitionError,
	StreamState,
};
use super::worker::{
	ConnectionState,
};
use super::msg::{
	SocketOption,
};
use super::handle::{
	StreamHandle,
};


impl From<StateTransitionError> for LuaError {
	fn from(other: StateTransitionError) -> Self {
		LuaError::ExternalError(Arc::new(other))
	}
}


impl SocketOption {
	pub(super) fn from_lua_args<'l>(_lua: &'l Lua, option: String, _value: LuaValue) -> Result<SocketOption, String> {
		match option.as_str() {
			"keepalive" => Ok(SocketOption::KeepAlive(true)),
			_ => Err(format!("socket option not supported: {}", option)),
		}
	}
}


pub(crate) fn set_listeners<'l>(ud: &LuaAnyUserData<'l>, listeners: LuaTable<'l>) -> LuaResult<()> {
	let tbl = ud.get_user_value::<LuaTable>()?;
	tbl.set(0, listeners)
}

pub(crate) fn get_listeners<'l>(ud: &LuaAnyUserData<'l>) -> LuaResult<LuaTable<'l>> {
	let tbl = ud.get_user_value::<LuaTable>()?;
	tbl.get::<_, LuaTable>(0)
}

pub(crate) fn wrapclient<'l>(
		lua: &'l Lua,
		(fd, addr, port, listeners, read_size, tls_ctx, extra): (RawFd, String, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaTable>)
		) -> LuaResult<Result<LuaAnyUserData<'l>, String>>
{
	let fd = strerror_ok!(fcntl(
		fd,
		FcntlArg::F_DUPFD_CLOEXEC(0),
	));
	// this is probably the worst one could do... let's hope the syscalls will quickly let this fail
	let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
	strerror_ok!(sock.set_nonblocking(true));
	let sock: std::net::TcpStream = sock.into();

	// extra is required, we MUST have the server name...
	let servername = match extra.as_ref() {
		Some(extra) => match extra.get::<_, Option<LuaString>>("servername") {
			Ok(Some(v)) => match webpki::DNSNameRef::try_from_ascii(v.as_bytes()) {
				Ok(v) => Some(v.to_owned()),
				Err(e) => return Ok(Err(format!("servername is not a DNSName: {}", e))),
			},
			Ok(None) => None,
			Err(e) => return Ok(Err(format!("invalid option servername (required for TLS, and TLS context is given): {}", e))),
		},
		None => None,
	};

	let tls_ctx_arc = tls_ctx.map(|x| { x.0 });
	let tls_ctx_ref = tls_ctx_arc.as_ref().map(|x| { &**x });

	let tls_state = match (tls_ctx_ref, servername) {
		(Some(tls::TlsConfig::Client{cfg, recorder}), Some(name)) => {
			PreTlsConfig::ClientSide(name, cfg.clone(), recorder.clone())
		},
		(Some(tls::TlsConfig::Client{..}), None) => {
			return Ok(Err(format!("client-side TLS context given, but no target server name")))
		},
		(Some(tls::TlsConfig::Server{cfg, ..}), _) => {
			PreTlsConfig::ServerSide(cfg.clone())
		},
		(None, _) => PreTlsConfig::None,
	};

	let mut cfg = CONFIG.read().unwrap().stream;
	cfg.read_size = read_size;

	with_runtime_lua!{
		let sock = TcpStream::from_std(sock)?;
		let handle = StreamHandle::wrap_state(lua, ConnectionState::Plain{sock}, listeners.clone(), (addr, port), StreamState::Plain(tls_state), cfg)?;
		may_call_listener(&listeners, "onconnect", handle.clone())?;
		Ok(Ok(handle))
	}
}

pub(crate) fn addclient<'l>(
		lua: &'l Lua,
		(addr, port, listeners, read_size, tls_ctx, _typ, extra): (LuaValue, u16, LuaTable, usize, Option<tls::TlsConfigHandle>, Option<LuaString>, Option<LuaTable>)
		) -> LuaResult<Result<LuaAnyUserData<'l>, String>>
{
	// TODO: honour the typ somehow? :)
	let addr = strerror_ok!(conversion::to_ipaddr(&addr));
	let addr = SocketAddr::new(addr, port);

	let tls_ctx = match tls_ctx {
		None => None,
		Some(tls_ctx) => match &*tls_ctx.0 {
			tls::TlsConfig::Client{cfg, recorder} => Some((cfg.clone(), recorder.clone())),
			_ => return Ok(Err(format!("non-client TLS config passed to client socket"))),
		}
	};

	// extra is required, we MUST have the server name...
	let tls_config = match (tls_ctx, extra.as_ref()) {
		(Some((cfg, recorder)), Some(extra)) => {
			let servername = match extra.get::<_, Option<LuaString>>("servername") {
				Ok(Some(v)) => v,
				Ok(None) => return Ok(Err(format!("missing option servername (required for TLS, and TLS context is given)"))),
				Err(e) => return Ok(Err(format!("invalid option servername (required for TLS, and TLS context is given): {}", e))),
			};
			let servername = match webpki::DNSNameRef::try_from_ascii(servername.as_bytes()) {
				Ok(v) => v,
				Err(e) => return Ok(Err(format!("servername is not a DNSName: {}", e))),
			};
			Some((servername.to_owned(), cfg, recorder))
		},
		(Some(_), None) => {
			return Ok(Err(format!("cannot connect via TLS without a servername")))
		},
		(None, None) | (None, Some(_)) => None,
	};

	let (connect_cfg, mut stream_cfg) = {
		let config = CONFIG.read().unwrap();
		(config.client, config.stream)
	};
	stream_cfg.read_size = read_size;

	with_runtime_lua!{
		Ok(Ok(StreamHandle::connect(lua, addr, listeners, tls_config, connect_cfg, stream_cfg)?))
	}
}
