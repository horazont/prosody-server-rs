use mlua::prelude::*;

use std::cell::Ref;
use std::collections::HashMap;
use std::io;
use std::ffi::OsStr;
use std::fs::{File, read_dir};
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


#[derive(Clone)]
pub(crate) enum TlsConfig {
	Server{
		cfg: Arc<rustls::ServerConfig>,
		resolver: Arc<DefaultingSNIResolver>,
	},
	Client{
		cfg: Arc<rustls::ClientConfig>
	},
}

#[derive(Clone)]
pub(crate) struct TlsConfigHandle(pub(crate) Arc<TlsConfig>);

impl TlsConfigHandle {
	pub(crate) fn get_ref_from_lua<'l>(v: &'l LuaAnyUserData<'l>) -> LuaResult<Ref<'l, Self>> {
		v.borrow()
	}

	pub(crate) fn as_ref(&self) -> &TlsConfig {
		&*self.0
	}
}

impl LuaUserData for TlsConfigHandle {
	fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
		methods.add_method("set_sni_host", |_, this: &Self, (hostname, cert, key): (String, String, String)| -> LuaResult<Result<bool, String>> {
			Ok(Err("to be implemented".into()))
		});
	}
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

fn certificatekey_from_lua<'l>(tbl: &'l LuaTable, lua: &'l Lua) -> LuaResult<Option<rustls::sign::CertifiedKey>> {
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

fn cast_option_value<'l, T: FromLua<'l>>(lua: &'l Lua, name: &str, v: LuaValue<'l>) -> Result<T, String> {
	match T::from_lua(v, lua) {
		Ok(v) => Ok(v),
		Err(e) => Err(format!("invalid value for {:?} option ({})", name, e)),
	}
}

fn borrow_str<'l>(lua: &'l Lua, name: &str, v: &'l LuaValue<'l>) -> Result<&'l str, String> {
	match v {
		LuaValue::String(ref s) => {
			match s.to_str() {
				Ok(v) => Ok(v),
				Err(e) => Err(format!("invalid value for {:?} option (invalid UTF-8)", name)),
			}
		},
		_ => Err(format!("invalid value for {:?} option (invalid type, expected str)", name)),
	}
}

fn parse_server_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let resolver = DefaultingSNIResolver::new();
	let default_keypair = match certificatekey_from_lua(&config, lua) {
		Ok(v) => v,
		Err(e) => return Ok(Err(format!("invalid keypair: {}", e))),
	};
	if let Some(default_keypair) = default_keypair {
		resolver.set_default_keypair(default_keypair);
	}
	let resolver = Arc::new(resolver);

	let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
	// TODO: handle verify in some way
	for kv in config.pairs::<LuaString, LuaValue>() {
		let (k, v) = match kv {
			Ok(kv) => kv,
			// skip invalid keys
			Err(e) => continue,
		};
		let k = match k.to_str() {
			Ok(k) => k,
			// skip invalid keys
			Err(e) => continue,
		};
		// TODO...
	}
	cfg.versions = vec![rustls::ProtocolVersion::TLSv1_2, rustls::ProtocolVersion::TLSv1_3];
	cfg.cert_resolver = resolver.clone();
	cfg.ignore_client_order = true;

	Ok(Ok(lua.create_userdata(TlsConfigHandle(Arc::new(TlsConfig::Server{
		cfg: Arc::new(cfg),
		resolver,
	})))?))
}

macro_rules! strerror {
	($e:expr) => {
		match $e {
			Ok(v) => v,
			Err(e) => return Ok(Err(format!("{}", e))),
		}
	}
}

struct NullVerifier();

impl rustls::ServerCertVerifier for NullVerifier {
	fn verify_server_cert(
			&self,
			roots: &rustls::RootCertStore,
			presented_certs: &[rustls::Certificate],
			dns_name: webpki::DNSNameRef<'_>,
			ocsp_response: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError>
	{
		Ok(rustls::ServerCertVerified::assertion())
	}
}

fn parse_client_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let mut cfg = rustls::ClientConfig::new();
	for kv in config.pairs::<LuaString, LuaValue>() {
		let (k, v) = match kv {
			Ok(kv) => kv,
			// skip invalid keys
			Err(e) => continue,
		};
		let k = match k.to_str() {
			Ok(k) => k,
			// skip invalid keys
			Err(e) => continue,
		};
		match k {
			"cafile" => {
				let fname = strerror!(borrow_str(lua, k, &v));
				let f = strerror!(File::open(fname));
				let _ = cfg.root_store.add_pem_file(&mut io::BufReader::new(f));
			},
			"capath" => {
				let dirname = strerror!(borrow_str(lua, k, &v));
				for entry in strerror!(read_dir(dirname)) {
					let entry = match entry {
						Ok(entry) => entry,
						Err(_) => continue,
					};
					let f = strerror!(File::open(entry.path()));
					let _ = cfg.root_store.add_pem_file(&mut io::BufReader::new(f));
				}
			},
			"verify" => {
				let vs = match v {
					LuaValue::Table(_) => {
						strerror!(Vec::<String>::from_lua(v, lua))
					},
					LuaValue::String(_) => {
						let value = strerror!(borrow_str(lua, k, &v));
						vec![value.into()]
					},
					_ => return Ok(Err(format!("invalid value for {:?} option (expected str or table)", k))),
				};
				for v in vs {
					match v.as_str() {
						"none" => cfg.dangerous().set_certificate_verifier(
							Arc::new(NullVerifier())
						),
						"peer" => cfg.dangerous().set_certificate_verifier(
							Arc::new(rustls::WebPKIVerifier::new())
						),
						// no idea what this one is supposed to do?!
						"client_once" => (),
						_ => return Ok(Err(format!("invalid value for {:?}: {:?}", k, v)))
					}
				}
			},
			// ignore unknown keys(?)
			&_ => continue,
		}
	}
	Ok(Ok(lua.create_userdata(TlsConfigHandle(Arc::new(TlsConfig::Client{
		cfg: Arc::new(cfg),
	})))?))
}


pub(crate) fn new_tls_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	match config.get::<_, String>("mode") {
		Ok(v) if v == "server" => parse_server_config(lua, config),
		Ok(v) if v == "client" => Ok(Err("not yet implemented".into())),
		Ok(v) => Ok(Err(format!("must be either \"server\" or \"client\", got {:?}", v))),
		Err(e) => Ok(Err(format!("mode is absent or of invalid type: {}", e))),
	}
}
