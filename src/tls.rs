use mlua::prelude::*;

use std::cell::Ref;
use std::collections::HashMap;
use std::io;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, RwLock};

use tokio_rustls::rustls;

use rustls_pemfile;


pub(crate) struct DefaultingSNIResolver {
	default_keypair: RwLock<Option<rustls::sign::CertifiedKey>>,
	named_keypairs: RwLock<HashMap<String, rustls::sign::CertifiedKey>>,
}

impl DefaultingSNIResolver {
	fn new() -> Self {
		Self{
			default_keypair: RwLock::new(None),
			named_keypairs: RwLock::new(HashMap::new()),
		}
	}

	fn get_default(&self) -> Option<rustls::sign::CertifiedKey> {
		let default_keypair = self.default_keypair.read().unwrap();
		default_keypair.clone()
	}

	fn get_by_name(&self, name: &'_ str) -> Option<rustls::sign::CertifiedKey> {
		let by_name = {
			let keypairs = self.named_keypairs.read().unwrap();
			keypairs.get(name).cloned()
		};
		match by_name {
			Some(v) => return Some(v),
			None => self.get_default(),
		}
	}

	fn set_default_keypair(&self, keypair: rustls::sign::CertifiedKey) {
		*self.default_keypair.write().unwrap() = Some(keypair)
	}
}

impl rustls::ResolvesServerCert for DefaultingSNIResolver {
	fn resolve(&self, client_hello: rustls::ClientHello<'_>) -> Option<rustls::sign::CertifiedKey> {
		match client_hello.server_name() {
			Some(name) => self.get_by_name(name.into()),
			None => self.get_default(),
		}
	}
}


pub(crate) enum TlsConfig {
	Server{
		cfg: Arc<rustls::ServerConfig>,
		resolver: Arc<DefaultingSNIResolver>,
	},
	Client(Arc<rustls::ClientConfig>),
}

impl TlsConfig {
	pub(crate) fn get_ref_from_lua<'l>(v: &'l LuaAnyUserData<'l>) -> LuaResult<Ref<'l, Self>> {
		v.borrow()
	}
}

impl LuaUserData for TlsConfig {
	// TODO: all the SNI stuff
}

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
	let key = match read_first_key(OsStr::from_bytes(key_file.as_bytes())) {
		Ok(v) => v,
		Err(e) => return Err(LuaError::RuntimeError(format!("failed to load key from {}: {}", key_file.to_string_lossy(), e))),
	};
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

fn parse_server_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let resolver = DefaultingSNIResolver::new();
	let default_keypair = match certificatekey_from_lua(config, lua) {
		Ok(v) => v,
		Err(e) => return Ok(Err(format!("invalid keypair: {}", e))),
	};
	if let Some(default_keypair) = default_keypair {
		resolver.set_default_keypair(default_keypair);
	}
	let resolver = Arc::new(resolver);

	let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
	cfg.versions = vec![rustls::ProtocolVersion::TLSv1_2, rustls::ProtocolVersion::TLSv1_3];
	cfg.cert_resolver = resolver.clone();
	cfg.ignore_client_order = true;

	Ok(Ok(lua.create_userdata(TlsConfig::Server{
		cfg: Arc::new(cfg),
		resolver,
	})?))
}


pub(crate) fn new_tls_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	match config.get::<_, String>("mode") {
		Ok(v) if v == "server" => parse_server_config(lua, config),
		Ok(v) if v == "client" => todo!(),
		Ok(v) => Ok(Err(format!("must be either \"server\" or \"client\", got {:?}", v))),
		Err(e) => Ok(Err(format!("mode is absent or of invalid type: {}", e))),
	}
}
