use mlua::prelude::*;

use std::borrow::Cow;
use std::net::SocketAddr;

use bytes::Bytes;

use tokio::sync::mpsc;

use crate::cert;
use crate::conversion::opaque;
use crate::tls;
use crate::verify;

use super::state::{
	StreamState,
};
use super::msg::{
	ControlMessage,
	SocketOption,
};
use super::lua::{
	set_listeners,
	to_servername,
};


pub(super) enum AddrStr {
	Unspecified,
	InetAny{
		addr: String,
		port: u16,
	},
	Unix{
		path: String,
	},
}

impl AddrStr {
	fn addr(&self) -> Option<&str> {
		match self {
			Self::Unspecified => None,
			Self::InetAny{addr, ..} => Some(&addr),
			Self::Unix{path} => Some(&path),
		}
	}

	fn port(&self) -> Option<u16> {
		match self {
			Self::InetAny{port, ..} => Some(*port),
			Self::Unspecified => None,
			Self::Unix{..} => None,
		}
	}
}

impl From<SocketAddr> for AddrStr {
	fn from(other: SocketAddr) -> Self {
		Self::InetAny{
			addr: other.ip().to_string(),
			port: other.port(),
		}
	}
}

impl From<std::os::unix::net::SocketAddr> for AddrStr {
	fn from(other: std::os::unix::net::SocketAddr) -> Self {
		match other.as_pathname() {
			Some(v) => Self::Unix{
				path: v.to_string_lossy().into(),
			},
			None => Self::Unspecified
		}
	}
}

pub(super) enum Kind {
	Server,
	Client,
}

pub(crate) struct StreamHandle {
	tx: mpsc::UnboundedSender<ControlMessage>,
	state: StreamState,
	kind: Kind,
	local: AddrStr,
	remote: AddrStr,
}

impl StreamHandle {
	fn send_set_option(&self, option: SocketOption) {
		let _ = self.tx.send(ControlMessage::SetOption(option));
	}
}

impl LuaUserData for StreamHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("ip", |_, this: &Self, _: ()| -> LuaResult<Option<String>> {
			let addr = match this.kind {
				Kind::Server => this.local.addr(),
				Kind::Client => this.remote.addr(),
			}.map(|x| { x.to_string() });
			Ok(addr)
		});

		methods.add_method("port", |_, this: &Self, _: ()| -> LuaResult<Option<u16>> {
			match this.kind {
				Kind::Server => Ok(this.local.port()),
				Kind::Client => Ok(this.remote.port()),
			}
		});

		methods.add_method("clientport", |_, this: &Self, _: ()| -> LuaResult<Option<u16>> {
			match this.kind {
				Kind::Server => Ok(this.remote.port()),
				Kind::Client => Ok(this.local.port()),
			}
		});

		methods.add_method("serverport", |_, this: &Self, _: ()| -> LuaResult<Option<u16>> {
			match this.kind {
				Kind::Server => Ok(this.local.port()),
				Kind::Client => Ok(this.remote.port()),
			}
		});

		methods.add_method("ssl", |_, this: &Self, _: ()| -> LuaResult<bool> {
			Ok(match this.state {
				StreamState::Tls{..} => true,
				_ => false,
			})
		});

		methods.add_method("ssl_info", |lua, this: &Self, _: ()| -> LuaResult<Option<LuaTable>> {
			match &this.state {
				StreamState::Tls{info, ..} => Ok(Some(info.handshake.to_lua_table(lua)?)),
				_ => Ok(None)
			}
		});

		methods.add_method("ssl_peercertificate", |_, this, _: ()| -> LuaResult<Option<cert::ParsedCertificate>> {
			match &this.state {
				StreamState::Tls{info, ..} => match &info.verify {
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
				StreamState::Tls{info, ..} => match &info.verify {
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
			let servername = match servername.as_ref().map(|x| { to_servername(x) }) {
				Some(v) => Some(v?),
				None => None,
			};
			let msg = this.state.start_tls(ctx_ref, servername)?;
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

impl StreamHandle {
	pub(super) fn new(
		state: StreamState,
		kind: Kind,
		local: AddrStr,
		remote: AddrStr,
	) -> (Self, mpsc::UnboundedReceiver<ControlMessage>) {
		let (tx, rx) = mpsc::unbounded_channel();
		(Self{
			tx,
			state,
			kind,
			local,
			remote,
		}, rx)
	}

	pub(crate) fn state_mut(&mut self) -> &mut StreamState {
		&mut self.state
	}
}
