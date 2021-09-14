use mlua::prelude::*;

use std::convert::TryInto;
use std::error;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;


#[derive(Debug, Clone)]
pub(crate) struct OpaqueError(String);

#[inline]
pub(crate) fn opaque<T: Into<String>>(other: T) -> OpaqueError {
	other.into().into()
}

impl fmt::Display for OpaqueError {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl error::Error for OpaqueError {}

impl From<String> for OpaqueError {
	fn from(other: String) -> Self {
		Self(other)
	}
}

impl From<&str> for OpaqueError {
	fn from(other: &str) -> Self {
		Self(other.to_string())
	}
}

impl From<OpaqueError> for LuaError {
	fn from(other: OpaqueError) -> Self {
		LuaError::ExternalError(Arc::new(other))
	}
}


#[macro_export]
macro_rules! strerror {
	($e:expr) => {
		match $e {
			Ok(v) => v,
			Err(e) => return Err(e.to_string()),
		}
	}
}


#[macro_export]
macro_rules! strerror_ok {
	($e:expr) => {
		match $e {
			Ok(v) => v,
			Err(e) => return Ok(Err(e.to_string())),
		}
	}
}


pub(crate) fn borrow_str<'l>(v: &'l LuaValue<'l>) -> Result<&'l str, String> {
	match v {
		LuaValue::String(s) => match s.to_str() {
			Ok(v) => Ok(v),
			Err(e) => Err(format!("invalid string: {}", e)),
		},
		_ => Err(format!("expected string, found {}", v.type_name())),
	}
}


pub(crate) fn to_ipaddr<'l>(addr: &LuaValue<'l>) -> Result<IpAddr, String> {
	let addr = borrow_str(&addr)?;
	if addr == "*" {
		Ok(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)))
	} else {
		match addr.parse::<IpAddr>() {
			Ok(v) => Ok(v),
			Err(e) => Err(format!("invalid IP address ({}): {}", e, addr)),
		}
	}
}


pub(crate) fn to_duration<'l>(v: LuaValue) -> LuaResult<Duration> {
	match v {
		LuaValue::Number(fsecs) => {
			let secs: u64 = match (fsecs as i64).try_into() {
				Ok(v) => v,
				Err(e) => return Err(LuaError::FromLuaConversionError{
					from: v.type_name(),
					to: "Duration",
					message: Some(e.to_string()),
				}),
			};
			let nanos = (fsecs.fract() * 1e9) as u32;
			Ok(Duration::new(secs, nanos))
		},
		LuaValue::Integer(secs) => match secs.try_into() {
			Ok(v) => Ok(Duration::new(v, 0)),
			Err(e) => Err(LuaError::FromLuaConversionError{
				from: v.type_name(),
				to: "Duration",
				message: Some(e.to_string()),
			})
		},
		_ => Err(LuaError::FromLuaConversionError{
			from: v.type_name(),
			to: "Duration",
			message: Some("number required".to_string()),
		}),
	}
}
