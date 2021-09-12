use mlua::prelude::*;

use std::convert::TryInto;
use std::net::IpAddr;
use std::time::Duration;


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
