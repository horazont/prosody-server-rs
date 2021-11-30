use mlua::prelude::*;

use std::convert::TryInto;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use tokio::net::TcpStream;

use tokio_rustls::rustls;
use tokio_rustls::server;
use tokio_rustls::webpki;

use nix::{
	fcntl::FcntlArg,
	fcntl::fcntl,
};

use crate::{
	strerror_ok,
	with_runtime_lua,
};
use crate::config;
use crate::core::{
	may_call_listener,
	LuaRegistryHandle,
	Spawn,
};
use crate::config::CONFIG;
use crate::conversion;
use crate::tls;
use crate::verify;

use super::connect::{
	ConnectWorker,
};
use super::state::{
	PreTlsConfig,
	StateTransitionError,
	StreamState,
};
use super::msg::{
	SocketOption,
};
use super::handle::{
	StreamHandle,
	Kind,
	AddrStr,
};
use super::worker::{
	StreamWorker,
	FdStream,
	AnyStream,
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

fn prep_handle<'l>(
		lua: &'l Lua,
		handle: StreamHandle,
		listeners: LuaTable,
) -> LuaResult<(LuaAnyUserData<'l>, LuaRegistryHandle)> {
	let handle = lua.create_userdata(handle)?;
	let data = lua.create_table_with_capacity(0, 1)?;
	handle.set_user_value(data)?;
	set_listeners(&handle, listeners)?;
	let reg_handle = lua.create_registry_value(handle.clone())?.into();
	Ok((handle, reg_handle))
}

fn spawn_stream_worker<'l>(
		lua: &'l Lua,
		conn: FdStream,
		listeners: LuaTable,
		state: StreamState,
		kind: Kind,
		local: AddrStr,
		remote: AddrStr,
		cfg: config::StreamConfig
) -> LuaResult<LuaAnyUserData<'l>> {
	let (handle, rx) = StreamHandle::new(
		state,
		kind,
		local,
		remote,
	);
	let (handle, reg_handle) = prep_handle(
		lua,
		handle,
		listeners,
	)?;

	StreamWorker::new(
		rx,
		conn,
		cfg,
		reg_handle,
	).spawn();
	Ok(handle)
}

fn spawn_connect_worker<'l>(
		lua: &'l Lua,
		addr: SocketAddr,
		listeners: LuaTable,
		tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
		connect_cfg: config::ClientConfig,
		stream_cfg: config::StreamConfig,
) -> LuaResult<LuaAnyUserData<'l>> {
	let (handle, rx) = StreamHandle::new(
		// we might establish TLS right away, in that case it doesn't matter
		StreamState::Connecting(PreTlsConfig::None),
		Kind::Client,
		// local address is not known until connect is done
		AddrStr::Unspecified,
		addr.into(),
	);
	let (handle, reg_handle) = prep_handle(
		lua,
		handle,
		listeners,
	)?;

	ConnectWorker::new(
		rx,
		addr,
		tls_config,
		connect_cfg,
		stream_cfg,
		reg_handle,
	).spawn();
	Ok(handle)
}

pub(crate) fn spawn_accepted_tcp_worker<'l>(
		lua: &'l Lua,
		conn: TcpStream,
		listeners: LuaTable,
		remoteaddr: Option<SocketAddr>,
		cfg: config::StreamConfig,
) -> LuaResult<LuaAnyUserData<'l>> {
	let remoteaddr = match remoteaddr {
		Some(remoteaddr) => remoteaddr.into(),
		None => conn.peer_addr()?.into(),
	};
	let localaddr = conn.local_addr()?.into();
	spawn_stream_worker(
		lua,
		conn.into(),
		listeners,
		StreamState::Plain(PreTlsConfig::None),
		Kind::Server,
		localaddr,
		remoteaddr,
		cfg,
	)
}

pub(crate) fn spawn_accepted_tlstcp_worker<'l>(
		lua: &'l Lua,
		conn: server::TlsStream<TcpStream>,
		listeners: LuaTable,
		remoteaddr: Option<SocketAddr>,
		info: tls::Info,
		cfg: config::StreamConfig,
) -> LuaResult<LuaAnyUserData<'l>> {
	let remoteaddr = match remoteaddr {
		Some(remoteaddr) => remoteaddr.into(),
		None => conn.get_ref().0.peer_addr()?.into(),
	};
	let localaddr = conn.get_ref().0.local_addr()?.into();
	spawn_stream_worker(
		lua,
		conn.into(),
		listeners,
		StreamState::Tls{info},
		Kind::Server,
		localaddr,
		remoteaddr,
		cfg,
	)
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
	let sock = strerror_ok!(AnyStream::try_from_raw_fd(fd));

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
		(Some(tls::TlsConfig::Server{cfg, recorder, ..}), _) => {
			PreTlsConfig::ServerSide(cfg.clone(), recorder.clone())
		},
		(None, _) => PreTlsConfig::None,
	};

	let mut cfg = CONFIG.read().unwrap().stream;
	cfg.read_size = read_size;

	with_runtime_lua!{
		let localaddr = sock.local_addr_str()?;
		let handle = spawn_stream_worker(
			lua,
			sock.try_into()?,
			listeners.clone(),
			StreamState::Plain(tls_state),
			Kind::Client,
			localaddr,
			AddrStr::InetAny{addr, port},
			cfg,
		)?;
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
		let handle = spawn_connect_worker(
			lua,
			addr,
			listeners,
			tls_config,
			connect_cfg,
			stream_cfg,
		)?;
		Ok(Ok(handle))
	}
}
