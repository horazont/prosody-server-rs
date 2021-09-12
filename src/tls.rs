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

use crate::strerror_ok;
use crate::conversion;
use crate::verify;


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

	fn get_by_name(&self, name: webpki::DNSNameRef) -> Option<rustls::sign::CertifiedKey> {
		let name: &str = name.into();
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

	fn set_keypair(&self, name: webpki::DNSNameRef, keypair: rustls::sign::CertifiedKey) {
		let name: &str = name.into();
		let mut keypairs = self.named_keypairs.write().unwrap();
		keypairs.insert(name.to_string(), keypair);
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
		cfg: Arc<rustls::ClientConfig>,
		recorder: Arc<verify::RecordingVerifier>,
	},
}

impl TlsConfig {
	fn set_sni_host<H: AsRef<[u8]>, C: AsRef<Path>, K: AsRef<Path>>(&self, hostname: H, cert: C, key: K) -> io::Result<()> {
		match self {
			Self::Server{resolver, ..} => {
				let hostname = hostname.as_ref();
				let hostname = match webpki::DNSNameRef::try_from_ascii(hostname) {
					Ok(v) => v,
					Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid hostname ({})", e))),
				};
				let (certs, key) = read_keypair(cert, key)?;
				let key = match rustls::sign::RSASigningKey::new(&key) {
					Ok(v) => v,
					Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid RSA key encountered")),
				};
				resolver.set_keypair(hostname, rustls::sign::CertifiedKey{
					cert: certs,
					key: Arc::new(Box::new(key)),
					ocsp: None,
					sct_list: None,
				});
				Ok(())
			},
			Self::Client{..} => Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot add SNI host to client context")),
		}
	}
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
		methods.add_method("set_sni_host", |_, this: &Self, (hostname, cert, key): (LuaString, LuaString, LuaString)| -> LuaResult<Result<bool, String>> {
			match this.0.set_sni_host(
					hostname.as_bytes(),
					OsStr::from_bytes(cert.as_bytes()),
					OsStr::from_bytes(key.as_bytes())
			) {
				Ok(()) => Ok(Ok(true)),
				Err(e) => Ok(Err(format!("failed to add SNI host with certificate {} and key {}: {}", cert.to_string_lossy(), key.to_string_lossy(), e))),
			}
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

fn read_keypair<C: AsRef<Path>, K: AsRef<Path>>(cert: C, key: K) -> io::Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
	let certs = read_certs(cert)?;
	let key = read_first_key(key)?;
	Ok((certs, key))
}

fn keypair_from_lua<'l>(tbl: &'l LuaTable) -> LuaResult<Option<(Vec<rustls::Certificate>, rustls::PrivateKey)>> {
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
	match read_keypair(
			OsStr::from_bytes(cert_file.as_bytes()),
			OsStr::from_bytes(key_file.as_bytes())
	) {
		Ok(keypair) => Ok(Some(keypair)),
		Err(e) => Err(LuaError::RuntimeError(format!("failed to load keypair from {} and {}: {}", cert_file.to_string_lossy(), key_file.to_string_lossy(), e))),
	}
}

fn certificatekey_from_lua<'l>(tbl: &'l LuaTable) -> LuaResult<Option<rustls::sign::CertifiedKey>> {
	let (certs, key) = match keypair_from_lua(tbl)? {
		Some(v) => v,
		None => return Ok(None)
	};
	let key = match rustls::sign::RSASigningKey::new(&key) {
		Ok(v) => v,
		Err(_) => return Err(LuaError::RuntimeError("invalid RSA key encountered".to_string())),
	};
	Ok(Some(rustls::sign::CertifiedKey{
		cert: certs,
		key: Arc::new(Box::new(key)),
		ocsp: None,
		sct_list: None,
	}))
}

fn borrow_named_str<'l>(name: &str, v: &'l LuaValue<'l>) -> Result<&'l str, String> {
	match conversion::borrow_str(v) {
		Ok(v) => Ok(v),
		Err(e) => Err(format!("invalid value for {:?}: {}", name, e)),
	}
}

fn parse_server_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let resolver = DefaultingSNIResolver::new();
	let default_keypair = match certificatekey_from_lua(&config) {
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
		let (k, _v) = match kv {
			Ok(kv) => kv,
			// skip invalid keys
			Err(_) => continue,
		};
		let _k = match k.to_str() {
			Ok(k) => k,
			// skip invalid keys
			Err(_) => continue,
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

fn parse_client_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let mut cfg = rustls::ClientConfig::new();
	match keypair_from_lua(&config)? {
		Some((certs, key)) => strerror_ok!(cfg.set_single_client_cert(certs, key)),
		None => (),
	};
	let mut recorder = verify::RecordingVerifier::new(
		Arc::new(rustls::WebPKIVerifier::new()),
		true,
	);
	for kv in config.pairs::<LuaString, LuaValue>() {
		let (k, v) = match kv {
			Ok(kv) => kv,
			// skip invalid keys
			Err(_) => continue,
		};
		let k = match k.to_str() {
			Ok(k) => k,
			// skip invalid keys
			Err(_) => continue,
		};
		match k {
			"cafile" => {
				let fname = strerror_ok!(borrow_named_str(k, &v));
				let f = strerror_ok!(File::open(fname));
				let _ = cfg.root_store.add_pem_file(&mut io::BufReader::new(f));
			},
			"capath" => {
				let dirname = strerror_ok!(borrow_named_str(k, &v));
				for entry in strerror_ok!(read_dir(dirname)) {
					let entry = match entry {
						Ok(entry) => entry,
						Err(_) => continue,
					};
					let f = strerror_ok!(File::open(entry.path()));
					let _ = cfg.root_store.add_pem_file(&mut io::BufReader::new(f));
				}
			},
			"verify" => {
				let vs = match v {
					LuaValue::Table(_) => {
						strerror_ok!(Vec::<String>::from_lua(v, lua))
					},
					LuaValue::String(_) => {
						let value = strerror_ok!(borrow_named_str(k, &v));
						vec![value.into()]
					},
					_ => return Ok(Err(format!("invalid value for {:?} option (expected str or table)", k))),
				};
				for v in vs {
					match v.as_str() {
						"none" => {
							recorder.strict = false;
						},
						"peer" => {
							recorder.strict = true;
						},
						"client_once" => continue,
						// no idea what this one is supposed to do?!
						_ => return Ok(Err(format!("invalid value for {:?}: {:?}", k, v)))
					};
				}
			},
			// ignore unknown keys(?)
			&_ => continue,
		}
	}

	let recorder = Arc::new(recorder);
	cfg.dangerous().set_certificate_verifier(recorder.clone());

	Ok(Ok(lua.create_userdata(TlsConfigHandle(Arc::new(TlsConfig::Client{
		cfg: Arc::new(cfg),
		recorder,
	})))?))
}


pub(crate) fn new_tls_config<'l>(lua: &'l Lua, config: LuaTable) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	match config.get::<_, String>("mode") {
		Ok(v) if v == "server" => parse_server_config(lua, config),
		Ok(v) if v == "client" => parse_client_config(lua, config),
		Ok(v) => Ok(Err(format!("must be either \"server\" or \"client\", got {:?}", v))),
		Err(e) => Ok(Err(format!("mode is absent or of invalid type: {}", e))),
	}
}
