use mlua::prelude::*;

use std::io;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls;

use rustls_pemfile;


fn read_certs<P: AsRef<Path>>(fname: P) -> io::Result<Vec<rustls::Certificate>> {
	let f = File::open(fname)?;
	let mut f = io::BufReader::new(f);
	Ok(rustls_pemfile::certs(&mut f)?.drain(..).map(|x| { rustls::Certificate(x) }).collect())
}


fn read_keys<P: AsRef<Path>>(fname: P) -> io::Result<Vec<rustls::PrivateKey>> {
	let f = File::open(fname)?;
	let mut f = io::BufReader::new(f);
	Ok(rustls_pemfile::rsa_private_keys(&mut f)?.drain(..).map(|x| { rustls::PrivateKey(x) }).collect())
}

fn read_first_key<P: AsRef<Path>>(fname: P) -> io::Result<rustls::PrivateKey> {
	let mut keys = read_keys(fname)?;
	if keys.len() == 0 {
		return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no key found in key file"));
	}
	Ok(keys.remove(0))
}

fn certificatekey_from_lua<'l>(tbl: LuaTable, lua: &'l Lua) -> LuaResult<Option<rustls::sign::CertifiedKey>> {
	let cert_file = tbl.get::<_, Option<LuaString>>("certificate")?;
	let key_file = tbl.get::<_, Option<LuaString>>("key")?;
	if cert_file.is_none() && key_file.is_none() {
		return Ok(None)
	}

	if cert_file.is_none() != key_file.is_none() {
		return Err(LuaError::RuntimeError(format!("either both certificate and key must be set, or both must be absent. make up your mind!")))
	}

	let cert_file = cert_file.unwrap();
	let key_file = key_file.unwrap();
	let certs = read_certs(OsStr::from_bytes(cert_file.as_bytes()))?;
	let key = read_first_key(OsStr::from_bytes(key_file.as_bytes()))?;
	let key = match rustls::sign::RSASigningKey::new(&key) {
		Ok(v) => v,
		Err(e) => return Err(LuaError::RuntimeError(format!("invalid RSA key"))),
	};
	Ok(Some(rustls::sign::CertifiedKey{
		cert: certs,
		key: Arc::new(Box::new(key)),
		ocsp: None,
		sct_list: None,
	}))
}


pub(crate) fn server_config_from_lua<'l>(tbl: LuaTable, lua: &'l Lua) -> LuaResult<rustls::ServerConfig> {
	let mut resolver = rustls::ResolvesServerCertUsingSNI::new();
	let sni_names = tbl.get::<_, Option<LuaTable>>("sni_names")?;
	match sni_names {
		Some(tbl) => {
			for r in tbl.pairs::<String, LuaTable>() {
				let (k, v) = r?;
				let certkey = match certificatekey_from_lua(v, lua)? {
					Some(ck) => ck,
					None => return Err(LuaError::RuntimeError(format!("certificate and key are required for SNI hosts; missing for {}", k)))
				};
				match resolver.add(&k, certkey) {
					Ok(_) => (),
					Err(e) => {
						return Err(LuaError::RuntimeError(format!("invalid certificate+key for name {}: {}", k, e)))
					}
				}
			}
		},
		None => return Err(LuaError::RuntimeError(format!("non-SNI usage is currently not supported :("))),
	}

	let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
	cfg.versions = vec![rustls::ProtocolVersion::TLSv1_2, rustls::ProtocolVersion::TLSv1_3];
	cfg.cert_resolver = Arc::new(resolver);
	cfg.ignore_client_order = true;

	Ok(cfg)
}
