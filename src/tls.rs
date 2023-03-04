/*!
# Rustls wrappers and configuration parsers
*/
use mlua::prelude::*;

use std::cell::Ref;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{read_dir, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, RwLock};

use tokio_rustls::rustls;

use rustls_pemfile;

use crate::conversion;
use crate::conversion::opaque;
use crate::strerror_ok;
use crate::verify;

pub(crate) struct DefaultingSNIResolver {
	default_keypair: RwLock<Option<Arc<rustls::sign::CertifiedKey>>>,
	named_keypairs: RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl DefaultingSNIResolver {
	fn new() -> Self {
		Self {
			default_keypair: RwLock::new(None),
			named_keypairs: RwLock::new(HashMap::new()),
		}
	}

	fn get_default(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
		let default_keypair = self.default_keypair.read().unwrap();
		default_keypair.clone()
	}

	fn get_by_name(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
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

	fn set_default_keypair(&self, keypair: Arc<rustls::sign::CertifiedKey>) {
		*self.default_keypair.write().unwrap() = Some(keypair)
	}

	fn set_keypair(&self, name: &str, keypair: Arc<rustls::sign::CertifiedKey>) {
		let name: &str = name.into();
		let mut keypairs = self.named_keypairs.write().unwrap();
		keypairs.insert(name.to_string(), keypair);
	}
}

impl rustls::server::ResolvesServerCert for DefaultingSNIResolver {
	fn resolve(
		&self,
		client_hello: rustls::server::ClientHello<'_>,
	) -> Option<Arc<rustls::sign::CertifiedKey>> {
		match client_hello.server_name() {
			Some(name) => self.get_by_name(name.into()),
			None => self.get_default(),
		}
	}
}

#[derive(Clone)]
pub(crate) enum TlsConfig {
	Server {
		cfg: Arc<rustls::ServerConfig>,
		resolver: Arc<DefaultingSNIResolver>,
		recorder: Arc<verify::RecordingClientVerifier>,
	},
	Client {
		cfg: Arc<rustls::ClientConfig>,
		recorder: Arc<verify::RecordingVerifier>,
	},
}

impl TlsConfig {
	fn set_sni_host<H: AsRef<str>, C: AsRef<Path>, K: AsRef<Path>>(
		&self,
		hostname: H,
		cert: C,
		key: K,
	) -> io::Result<()> {
		match self {
			Self::Server { resolver, .. } => {
				let hostname = hostname.as_ref();
				let (certs, key) = read_keypair(cert, key)?;
				let key = match rustls::sign::any_supported_type(&key) {
					Ok(v) => v,
					Err(_) => {
						return Err(io::Error::new(
							io::ErrorKind::InvalidData,
							"invalid private key encountered",
						))
					}
				};
				resolver.set_keypair(
					hostname,
					Arc::new(rustls::sign::CertifiedKey {
						cert: certs,
						key: key,
						ocsp: None,
						sct_list: None,
					}),
				);
				Ok(())
			}
			Self::Client { .. } => Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"cannot add SNI host to client context",
			)),
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
		methods.add_method(
			"set_sni_host",
			|_,
			 this: &Self,
			 (hostname, cert, key): (LuaString, LuaString, LuaString)|
			 -> LuaResult<Result<bool, String>> {
				match this.0.set_sni_host(
					hostname.to_str()?,
					OsStr::from_bytes(cert.as_bytes()),
					OsStr::from_bytes(key.as_bytes()),
				) {
					Ok(()) => Ok(Ok(true)),
					Err(e) => Ok(Err(format!(
						"failed to add SNI host with certificate {} and key {}: {}",
						cert.to_string_lossy(),
						key.to_string_lossy(),
						e
					))),
				}
			},
		);
	}
}

fn read_certs<P: AsRef<Path>>(fname: P) -> io::Result<Vec<rustls::Certificate>> {
	let f = File::open(fname)?;
	let mut f = io::BufReader::new(f);
	Ok(rustls_pemfile::certs(&mut f)?
		.drain(..)
		.map(|x| rustls::Certificate(x))
		.collect())
}

fn read_keys<P: AsRef<Path>>(fname: P) -> io::Result<Vec<rustls::PrivateKey>> {
	let f = File::open(fname)?;
	let mut f = io::BufReader::new(f);
	let mut result = Vec::new();
	for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut f).transpose()) {
		match item? {
			rustls_pemfile::Item::X509Certificate(_) => (),
			rustls_pemfile::Item::RSAKey(v)
			| rustls_pemfile::Item::PKCS8Key(v)
			| rustls_pemfile::Item::ECKey(v) => result.push(rustls::PrivateKey(v)),
			_ => (),
		}
	}
	Ok(result)
}

fn read_first_key<P: AsRef<Path>>(fname: P) -> io::Result<rustls::PrivateKey> {
	let mut keys = read_keys(fname)?;
	if keys.len() == 0 {
		return Err(io::Error::new(
			io::ErrorKind::UnexpectedEof,
			"no key found in key file",
		));
	}
	Ok(keys.remove(0))
}

fn read_keypair<C: AsRef<Path>, K: AsRef<Path>>(
	cert: C,
	key: K,
) -> io::Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
	let certs = read_certs(cert)?;
	let key = read_first_key(key)?;
	Ok((certs, key))
}

fn keypair_from_lua<'l>(
	tbl: &'l LuaTable,
) -> LuaResult<Option<(Vec<rustls::Certificate>, rustls::PrivateKey)>> {
	let cert_file = tbl.get::<_, Option<LuaString>>("certificate")?;
	let key_file = tbl.get::<_, Option<LuaString>>("key")?;
	if cert_file.is_none() && key_file.is_none() {
		return Ok(None);
	}

	if cert_file.is_none() != key_file.is_none() {
		return Err(opaque("either both certificate and key must be set, or both must be absent. make up your mind!").into());
	}

	let cert_file = cert_file.unwrap();
	let key_file = key_file.unwrap();
	match read_keypair(
		OsStr::from_bytes(cert_file.as_bytes()),
		OsStr::from_bytes(key_file.as_bytes()),
	) {
		Ok(keypair) => Ok(Some(keypair)),
		Err(e) => Err(opaque(format!(
			"failed to load keypair from {} and {}: {}",
			cert_file.to_string_lossy(),
			key_file.to_string_lossy(),
			e
		))
		.into()),
	}
}

fn certificatekey_from_lua<'l>(tbl: &'l LuaTable) -> LuaResult<Option<rustls::sign::CertifiedKey>> {
	let (certs, key) = match keypair_from_lua(tbl)? {
		Some(v) => v,
		None => return Ok(None),
	};
	let key = match rustls::sign::any_supported_type(&key) {
		Ok(v) => v,
		Err(_) => return Err(opaque("invalid RSA key encountered").into()),
	};
	Ok(Some(rustls::sign::CertifiedKey {
		cert: certs,
		key: key,
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

fn read_rootstore_file<P: AsRef<Path>>(
	name: P,
	into: &mut rustls::RootCertStore,
) -> io::Result<()> {
	let f = File::open(name.as_ref())?;
	let mut f = io::BufReader::new(f);
	let mut certs = Vec::new();
	for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut f).transpose()) {
		match item {
			Ok(rustls_pemfile::Item::X509Certificate(cert)) => certs.push(cert),
			Ok(_) => continue,
			Err(_) => continue,
		}
	}
	into.add_parsable_certificates(&certs[..]);
	Ok(())
}

fn parse_server_config<'l>(
	lua: &'l Lua,
	config: LuaTable,
) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let resolver = DefaultingSNIResolver::new();
	let default_keypair = match certificatekey_from_lua(&config) {
		Ok(v) => v,
		Err(e) => return Ok(Err(format!("invalid keypair: {}", e))),
	};
	if let Some(default_keypair) = default_keypair {
		resolver.set_default_keypair(Arc::new(default_keypair));
	}
	let resolver = Arc::new(resolver);

	let mut root_store = rustls::RootCertStore::empty();
	let mut strict_verify = true;
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
				strerror_ok!(read_rootstore_file(fname, &mut root_store));
			}
			"capath" => {
				let dirname = strerror_ok!(borrow_named_str(k, &v));
				for entry in strerror_ok!(read_dir(dirname)) {
					let entry = match entry {
						Ok(entry) => entry,
						Err(_) => continue,
					};
					match entry.file_type() {
						Err(_) => continue,
						Ok(t) => {
							if !t.is_file() {
								continue;
							}
						}
					};
					strerror_ok!(read_rootstore_file(entry.path(), &mut root_store));
				}
			}
			"verifyext" => {
				let vs = match v {
					LuaValue::Table(_) => {
						strerror_ok!(Vec::<String>::from_lua(v, lua))
					}
					LuaValue::String(_) => {
						let value = strerror_ok!(borrow_named_str(k, &v));
						vec![value.into()]
					}
					_ => {
						return Ok(Err(format!(
							"invalid value for {:?} option (expected str or table)",
							k
						)))
					}
				};
				for v in vs {
					match v.as_str() {
						"lsec_continue" => {
							strict_verify = false;
						}
						"lsec_ignore_purpose" => continue,
						// no idea what this one is supposed to do?!
						_ => return Ok(Err(format!("invalid value for {:?}: {:?}", k, v))),
					};
				}
			}
			// ignore unknown keys(?)
			&_ => continue,
		}
	}

	let verifier = rustls::server::AllowAnyAnonymousOrAuthenticatedClient::new(root_store);
	let recorder = verify::RecordingClientVerifier::new(verifier, strict_verify);
	let recorder = Arc::new(recorder);

	let cfg = rustls::ServerConfig::builder()
		.with_safe_defaults()
		.with_client_cert_verifier(recorder.clone())
		.with_cert_resolver(resolver.clone());

	Ok(Ok(lua.create_userdata(TlsConfigHandle(Arc::new(
		TlsConfig::Server {
			cfg: Arc::new(cfg),
			resolver,
			recorder,
		},
	)))?))
}

fn parse_client_config<'l>(
	lua: &'l Lua,
	config: LuaTable,
) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	let mut root_store = rustls::RootCertStore::empty();
	let mut strict_verify = true;
	let keypair = keypair_from_lua(&config)?;
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
				strerror_ok!(read_rootstore_file(fname, &mut root_store));
			}
			"capath" => {
				let dirname = strerror_ok!(borrow_named_str(k, &v));
				for entry in strerror_ok!(read_dir(dirname)) {
					let entry = match entry {
						Ok(entry) => entry,
						Err(_) => continue,
					};
					match entry.file_type() {
						Err(_) => continue,
						Ok(t) => {
							if !t.is_file() {
								continue;
							}
						}
					};
					strerror_ok!(read_rootstore_file(entry.path(), &mut root_store));
				}
			}
			"verifyext" => {
				let vs = match v {
					LuaValue::Table(_) => {
						strerror_ok!(Vec::<String>::from_lua(v, lua))
					}
					LuaValue::String(_) => {
						let value = strerror_ok!(borrow_named_str(k, &v));
						vec![value.into()]
					}
					_ => {
						return Ok(Err(format!(
							"invalid value for {:?} option (expected str or table)",
							k
						)))
					}
				};
				for v in vs {
					match v.as_str() {
						"lsec_continue" => {
							strict_verify = false;
						}
						"lsec_ignore_purpose" => continue,
						// no idea what this one is supposed to do?!
						_ => return Ok(Err(format!("invalid value for {:?}: {:?}", k, v))),
					};
				}
			}
			// ignore unknown keys(?)
			&_ => continue,
		}
	}

	let recorder = Arc::new(verify::RecordingVerifier::new(
		Arc::new(rustls::client::WebPkiVerifier::new(root_store, None)),
		strict_verify,
	));
	let cfg = rustls::ClientConfig::builder()
		.with_safe_defaults()
		.with_custom_certificate_verifier(recorder.clone());

	let cfg = match keypair {
		Some((certs, key)) => strerror_ok!(cfg.with_single_cert(certs, key)),
		None => cfg.with_no_client_auth(),
	};

	Ok(Ok(lua.create_userdata(TlsConfigHandle(Arc::new(
		TlsConfig::Client {
			cfg: Arc::new(cfg),
			recorder,
		},
	)))?))
}

pub(crate) fn new_tls_config<'l>(
	lua: &'l Lua,
	config: LuaTable,
) -> LuaResult<Result<LuaAnyUserData<'l>, String>> {
	match config.get::<_, String>("mode") {
		Ok(v) if v == "server" => parse_server_config(lua, config),
		Ok(v) if v == "client" => parse_client_config(lua, config),
		Ok(v) => Ok(Err(format!(
			"must be either \"server\" or \"client\", got {:?}",
			v
		))),
		Err(e) => Ok(Err(format!("mode is absent or of invalid type: {}", e))),
	}
}

fn protocol_str(p: rustls::ProtocolVersion) -> &'static str {
	match p {
		rustls::ProtocolVersion::SSLv2 => "SSLv2",
		rustls::ProtocolVersion::SSLv3 => "SSLv3",
		rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0",
		rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1",
		rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
		rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
		rustls::ProtocolVersion::DTLSv1_0 => "DTLSv1.0",
		rustls::ProtocolVersion::DTLSv1_2 => "DTLSv1.2",
		rustls::ProtocolVersion::DTLSv1_3 => "DTLSv1.3",
		rustls::ProtocolVersion::Unknown(_) => "unknown",
	}
}

fn cipher_str(cs: rustls::SupportedCipherSuite) -> String {
	format!("{:?}", cs.suite())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HandshakeInfo {
	protocol: rustls::ProtocolVersion,
	cipher: rustls::SupportedCipherSuite,
}

impl From<&rustls::server::ServerConnection> for HandshakeInfo {
	fn from(other: &rustls::server::ServerConnection) -> Self {
		Self {
			protocol: other.protocol_version().unwrap(),
			cipher: other.negotiated_cipher_suite().unwrap(),
		}
	}
}

impl From<&rustls::client::ClientConnection> for HandshakeInfo {
	fn from(other: &rustls::client::ClientConnection) -> Self {
		Self {
			protocol: other.protocol_version().unwrap(),
			cipher: other.negotiated_cipher_suite().unwrap(),
		}
	}
}

impl HandshakeInfo {
	pub(crate) fn to_lua_table<'l>(&self, lua: &'l Lua) -> LuaResult<LuaTable<'l>> {
		let result = lua.create_table_with_capacity(0, 3)?;
		result.raw_set::<_, _>("compression", false)?;
		result.raw_set::<_, _>("protocol", protocol_str(self.protocol))?;
		result.raw_set::<_, _>("cipher", cipher_str(self.cipher))?;
		Ok(result)
	}
}

#[derive(Debug, Clone)]
pub(crate) struct Info {
	pub(crate) handshake: HandshakeInfo,
	pub(crate) verify: verify::VerificationRecord,
}
