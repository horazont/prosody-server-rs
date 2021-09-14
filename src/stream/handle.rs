use mlua::prelude::*;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use tokio_rustls::server;

use crate::cert;
use crate::config;
use crate::core::Spawn;
use crate::conversion::opaque;
use crate::tls;
use crate::verify;

use super::state::{
	PreTlsConfig,
	StreamState,
};
use super::msg::{
	ControlMessage,
	SocketOption,
};
use super::worker::{
	StreamWorker,
	ConnectionState,
};
use super::connect::{
	ConnectWorker,
};
use super::lua::set_listeners;


pub(crate) struct ConnectionHandle {
	tx: mpsc::UnboundedSender<ControlMessage>,
	state: StreamState,
	sockaddr: String,
	sockport: u16,
}

impl ConnectionHandle {
	fn send_set_option(&self, option: SocketOption) {
		let _ = self.tx.send(ControlMessage::SetOption(option));
	}
}

impl LuaUserData for ConnectionHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("ip", |_, this: &Self, _: ()| -> LuaResult<String> {
			Ok(this.sockaddr.clone())
		});

		methods.add_method("port", |_, this: &Self, _: ()| -> LuaResult<u16> {
			Ok(this.sockport)
		});

		methods.add_method("clientport", |_, this: &Self, _: ()| -> LuaResult<u16> {
			Ok(this.sockport)
		});

		methods.add_method("ssl", |_, this: &Self, _: ()| -> LuaResult<bool> {
			Ok(match this.state {
				StreamState::Tls{..} => true,
				_ => false,
			})
		});

		methods.add_method("ssl_info", |_, _this: &Self, _: ()| -> LuaResult<()> {
			// TODO: return something useful here
			Ok(())
		});

		methods.add_method("ssl_peercertificate", |_, this, _: ()| -> LuaResult<Option<cert::ParsedCertificate>> {
			match &this.state {
				StreamState::Tls{verify, ..} => match verify {
					verify::VerificationRecord::Unverified | verify::VerificationRecord::Failed{..} => {
						Ok(None)
					},
					verify::VerificationRecord::Passed{cert: certificate} => {
						Ok(cert::ParsedCertificate::from_der(Cow::Borrowed(&certificate.0)).ok())
					},
				},
				_ => Ok(None)
			}
		});

		methods.add_method("ssl_peerverification", |lua, this: &Self, _: ()| -> LuaResult<(bool, LuaTable)> {
			let reasons = lua.create_table()?;
			match &this.state {
				StreamState::Tls{verify, ..} => match verify {
					verify::VerificationRecord::Unverified => {
						reasons.raw_set(1, "verification disabled or did not complete")?;
						Ok((false, reasons))
					},
					verify::VerificationRecord::Passed{..} => {
						Ok((true, reasons))
					},
					verify::VerificationRecord::Failed{err} => {
						reasons.raw_set(1, format!("{}", err))?;
						Ok((true, reasons))
					},
				},
				_ => Ok((false, reasons))
			}
		});

		methods.add_method("block_reads", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::BlockReads);
			Ok(())
		});

		methods.add_method("pause_writes", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::BlockWrites);
			Ok(())
		});

		methods.add_method("resume_writes", |_, this: &Self, _: ()| -> LuaResult<()> {
			let _ = this.tx.send(ControlMessage::UnblockWrites);
			Ok(())
		});

		methods.add_method("setoption", |lua, this: &Self, name: String| -> LuaResult<(bool, Option<String>)> {
			let option = match SocketOption::from_lua_args(lua, name, LuaValue::Nil) {
				Ok(v) => v,
				Err(e) => return Ok((false, Some(e))),
			};
			this.send_set_option(option);
			Ok((true, None))
		});

		methods.add_method_mut("starttls", |_, this: &mut Self, (ctx, servername): (Option<tls::TlsConfigHandle>, Option<LuaString>)| -> LuaResult<()> {
			let ctx_arc = ctx.map(|x| { x.0 });
			let ctx_ref = ctx_arc.as_ref().map(|x| { &**x });
			let servername_ref = match servername.as_ref().map(|x| { webpki::DNSNameRef::try_from_ascii(x.as_bytes()) }) {
				Some(Ok(v)) => Some(v),
				Some(Err(e)) => return Err(opaque(format!("passed server name {:?} is invalid: {}", servername.unwrap().to_string_lossy(), e)).into()),
				None => None,
			};
			let msg = this.state.start_tls(ctx_ref, servername_ref)?;
			match this.tx.send(msg) {
				Ok(()) => Ok(()),
				Err(_) => return Err(opaque("socket already closed").into()),
			}
		});

		methods.add_method("write", |_, this: &Self, data: LuaString| -> LuaResult<usize> {
			let data: Bytes = Bytes::copy_from_slice(data.as_bytes());
			let len = data.len();
			match this.tx.send(ControlMessage::Write(data)) {
				Ok(_) => Ok(len),
				Err(_) => Ok(0),
			}
		});

		methods.add_method("close", |_, this: &Self, _: ()| -> LuaResult<()> {
			// this can only fail when the socket is already dead
			let _ = this.tx.send(ControlMessage::Close);
			Ok(())
		});

		methods.add_function("setlistener", |_, (this, listeners, data): (LuaAnyUserData, LuaTable, LuaValue)| -> LuaResult<()> {
			let old_listeners = this.get_user_value::<LuaTable>()?;
			match old_listeners.get::<_, Option<LuaFunction>>("ondetach")? {
				Some(func) => func.call::<_, ()>(this.clone())?,
				None => (),
			};
			set_listeners(&this, listeners.clone())?;
			match listeners.get::<_, Option<LuaFunction>>("onattach")? {
				Some(func) => func.call::<_, ()>((this.clone(), data))?,
				None => (),
			};
			Ok(())
		});

		methods.add_meta_function(LuaMetaMethod::Index, |_, (this, key): (LuaAnyUserData, LuaString)| -> LuaResult<LuaValue> {
			let data = this.get_user_value::<LuaTable>()?;
			data.raw_get::<_, LuaValue>(key)
		});

		methods.add_meta_function(LuaMetaMethod::NewIndex, |_, (this, key, value): (LuaAnyUserData, LuaString, LuaValue)| -> LuaResult<()> {
			let data = this.get_user_value::<LuaTable>()?;
			data.raw_set(key, value)
		});
	}
}

impl ConnectionHandle {
	pub(super) fn wrap_state<'l>(
			lua: &'l Lua,
			conn: ConnectionState,
			listeners: LuaTable,
			addr: (String, u16),
			state: StreamState,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			state,
			sockaddr: addr.0,
			sockport: addr.1,
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		StreamWorker::new(
			rx,
			conn,
			cfg,
			handle,
		).spawn();
		Ok(v)
	}

	pub(super) fn connect<'l>(
			lua: &'l Lua,
			addr: SocketAddr,
			listeners: LuaTable,
			tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
			connect_cfg: config::ClientConfig,
			stream_cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let (tx, rx) = mpsc::unbounded_channel();

		let v = lua.create_userdata(Self{
			tx,
			// we might establish TLS right away, in that case it doesn't matter
			state: StreamState::Connecting(PreTlsConfig::None),
			// this is actually correct because ip() is supposed to return the remote IP for clients
			sockaddr: format!("{}", addr.ip()),
			sockport: addr.port(),
		})?;
		let data = lua.create_table_with_capacity(0, 1)?;
		v.set_user_value(data)?;
		set_listeners(&v, listeners)?;
		let handle = lua.create_registry_value(v.clone())?.into();

		ConnectWorker::new(
			rx,
			addr,
			tls_config,
			connect_cfg,
			stream_cfg,
			handle,
		).spawn();
		Ok(v)
	}

	pub(crate) fn wrap_plain<'l>(
			lua: &'l Lua,
			conn: TcpStream,
			listeners: LuaTable,
			addr: Option<SocketAddr>,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::Plain{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), StreamState::Plain(PreTlsConfig::None), cfg)
	}

	pub(crate) fn wrap_tls_server<'l>(
			lua: &'l Lua,
			conn: server::TlsStream<TcpStream>,
			listeners: LuaTable,
			addr: Option<SocketAddr>,
			verify: verify::VerificationRecord,
			cfg: config::StreamConfig,
	) -> LuaResult<LuaAnyUserData<'l>> {
		let addr = match addr {
			Some(addr) => addr,
			None => conn.get_ref().0.local_addr()?,
		};
		Self::wrap_state(lua, ConnectionState::TlsServer{sock: conn}, listeners, (addr.ip().to_string(), addr.port()), StreamState::Tls{verify}, cfg)
	}

	pub(crate) fn state_mut(&mut self) -> &mut StreamState {
		&mut self.state
	}
}
