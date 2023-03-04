/*!
# Exposure of X.509 certificates to Lua
*/
use mlua::prelude::*;

use std::borrow::Cow;
use std::io;
use std::sync::Arc;

use x509_parser::{
	certificate::X509Certificate,
	extensions::{GeneralName, ParsedExtension, SubjectAlternativeName},
	nom, oid_registry,
	traits::FromDer,
};

use crate::conversion::opaque;

#[derive(Clone)]
pub(crate) struct ParsedCertificate {
	lifetime_bound: Arc<Vec<u8>>,
	parsed: X509Certificate<'static>,
}

impl ParsedCertificate {
	pub(crate) fn from_der(der: Cow<'_, Vec<u8>>) -> io::Result<Self> {
		let lifetime_bound = Arc::new(der.into_owned());
		// this type annotation is important to avoid accidentally transmuting something other than just the lifetime in the unsafe block below
		let parsed: X509Certificate<'_> = match X509Certificate::from_der(&lifetime_bound[..]) {
			Ok((_, parsed)) => parsed,
			Err(nom::Err::Failure(e)) | Err(nom::Err::Error(e)) => {
				return Err(io::Error::new(io::ErrorKind::InvalidData, e))
			}
			Err(nom::Err::Incomplete(_)) => {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"incomplete X.509 object",
				))
			}
		};
		let parsed: X509Certificate<'static> = unsafe { std::mem::transmute(parsed) };
		Ok(ParsedCertificate {
			lifetime_bound,
			parsed,
		})
	}

	pub(crate) fn parsed<'a>(&'a self) -> &X509Certificate<'a> {
		&self.parsed
	}
}

impl LuaUserData for ParsedCertificate {
	fn add_methods<'l, M: LuaUserDataMethods<'l, Self>>(methods: &mut M) {
		methods.add_method(
			"extensions",
			|_, this, _: ()| -> LuaResult<ExtensionsHandle> { Ok(ExtensionsHandle(this.clone())) },
		);

		methods.add_method("setencode", |_, _this, arg: LuaString| -> LuaResult<()> {
			if arg.as_bytes() == b"utf8" {
				Ok(())
			} else {
				Err(opaque(format!("unsupported certificate encoding: {:?}", arg)).into())
			}
		});

		methods.add_method("subject", |lua, this, _: ()| -> LuaResult<LuaTable> {
			// We are going to cheat a lot here...
			let oid = oid_registry::OID_X509_COMMON_NAME
				.to_id_string()
				.to_lua(lua)?;
			let mut cns: Vec<&str> = this
				.parsed()
				.subject()
				.iter_common_name()
				.filter_map(|x| x.as_str().ok())
				.collect();
			let ncns = if cns.len() <= i32::MAX as usize {
				cns.len() as i32
			} else {
				return Err(opaque("integer overflow while building subject table").into());
			};
			let result = lua.create_table_with_capacity(ncns, 0)?;
			for (i, cn) in cns.drain(..).enumerate() {
				let item = lua.create_table_with_capacity(0, 2)?;
				item.raw_set::<_, _>("oid", oid.clone())?;
				item.raw_set::<_, _>("value", cn.to_string().to_lua(lua)?)?;
				result.raw_set::<_, _>(i + 1, item)?;
			}
			Ok(result)
		});
	}
}

struct ExtensionsHandle(ParsedCertificate);

impl LuaUserData for ExtensionsHandle {
	fn add_methods<'l, M: LuaUserDataMethods<'l, Self>>(methods: &mut M) {
		methods.add_meta_method(
			LuaMetaMethod::Index,
			|lua, this, oid: LuaString| -> LuaResult<Option<LuaAnyUserData<'l>>> {
				let oid = match oid.to_str() {
					Ok(oid) => oid,
					// if it's not a valid string, we can't find a match anyway
					Err(_) => return Ok(None),
				};
				let oid = match oid.parse::<oid_registry::Oid>() {
					Ok(oid) => oid,
					Err(_) => return Ok(None),
				};
				if oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
					Ok(Some(lua.create_userdata(SANHandle(this.0.clone()))?))
				} else {
					Ok(None)
				}
			},
		);
	}
}

struct SANHandle(ParsedCertificate);

impl SANHandle {
	fn get<'a>(&'a self) -> Option<&'a SubjectAlternativeName<'a>> {
		for ext in self.0.parsed().extensions() {
			if ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
				match ext.parsed_extension() {
					ParsedExtension::SubjectAlternativeName(x) => return Some(x),
					_ => continue,
				}
			}
		}
		None
	}
}

impl LuaUserData for SANHandle {
	fn add_methods<'l, M: LuaUserDataMethods<'l, Self>>(methods: &mut M) {
		methods.add_meta_method(
			LuaMetaMethod::Index,
			|lua, this, key: LuaString| -> LuaResult<Option<LuaTable>> {
				let key = match key.to_str() {
					Ok(key) => key,
					// if it's not a valid string, we can't find a match anyway
					Err(_) => return Ok(None),
				};
				let sans = match this.get() {
					Some(v) => v,
					None => return Ok(None),
				};
				let iter = sans.general_names.iter();
				let mut names: Vec<&[u8]> = match key {
					"dNSName" => iter
						.filter_map(|n| match n {
							GeneralName::DNSName(n) => Some(n.as_bytes()),
							_ => None,
						})
						.collect(),
					"uniformResourceIdentifier" => iter
						.filter_map(|n| match n {
							GeneralName::URI(n) => Some(n.as_bytes()),
							_ => None,
						})
						.collect(),
					oid => {
						let oid = match oid.parse::<oid_registry::Oid>() {
							Ok(oid) => oid,
							Err(_) => return Ok(None),
						};
						iter.filter_map(|n| match n {
							GeneralName::OtherName(noid, n) if noid == &oid => Some(*n),
							_ => None,
						})
						.collect()
					}
				};
				let nnames = if names.len() <= i32::MAX as usize {
					names.len() as i32
				} else {
					return Err(opaque("integer overflow while building name table").into());
				};
				let tbl = lua.create_table_with_capacity(nnames, 0)?;
				for (i, name) in names.drain(..).enumerate() {
					tbl.raw_set::<_, _>(i + 1, lua.create_string(name)?)?;
				}
				Ok(Some(tbl))
			},
		);
	}
}
