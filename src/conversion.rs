use mlua::prelude::*;

use std::net::IpAddr;


#[macro_export]
macro_rules! strerror {
	($e:expr) => {
		match $e {
			Ok(v) => v,
			Err(e) => return Err(format!("{}", e)),
		}
	}
}


#[macro_export]
macro_rules! strerror_ok {
	($e:expr) => {
		match $e {
			Ok(v) => v,
			Err(e) => return Ok(Err(format!("{}", e))),
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
