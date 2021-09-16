use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use tokio_rustls::TlsConnector;

use crate::config;
use crate::core::{
	MAIN_CHANNEL,
	LuaRegistryHandle,
	Message,
	Spawn,
};
use crate::ioutil::iotimeout;
use crate::verify;

use super::msg::{
	ControlMessage,
};
use super::worker::{
	StreamWorker,
};


pub(super) struct ConnectWorker {
	rx: mpsc::UnboundedReceiver<ControlMessage>,
	addr: SocketAddr,
	connect_cfg: config::ClientConfig,
	stream_cfg: config::StreamConfig,
	tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
	handle: LuaRegistryHandle,
}

impl ConnectWorker {
	pub(super) fn new(
			rx: mpsc::UnboundedReceiver<ControlMessage>,
			addr: SocketAddr,
			tls_config: Option<(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>)>,
			connect_cfg: config::ClientConfig,
			stream_cfg: config::StreamConfig,
			handle: LuaRegistryHandle,
	) -> Self {
		Self{
			rx,
			addr,
			tls_config,
			connect_cfg,
			stream_cfg,
			handle,
		}
	}

	async fn run(self) {
		let sock = match iotimeout(self.connect_cfg.connect_timeout, TcpStream::connect(self.addr), "connection timed out").await {
			Ok(sock) => sock,
			Err(e) => {
				MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
					handle: self.handle,
					error: Some(Box::new(e)),
				}).await;
				return;
			},
		};
		let conn = match self.tls_config {
			Some((name, config, recorder)) => {
				let connector: TlsConnector = config.into();
				let handshake_timeout = self.stream_cfg.ssl_handshake_timeout;
				let (verify, result) = recorder.scope(async move {
					iotimeout(handshake_timeout, connector.connect(name.as_ref(), sock), "timeout during TLS handshake").await
				}).await;
				let sock = match result {
					Ok(sock) => sock,
					Err(e) => {
						MAIN_CHANNEL.fire_and_forget(Message::Disconnect{
							handle: self.handle,
							error: Some(Box::new(e)),
						}).await;
						return;
					},
				};
				match MAIN_CHANNEL.send(Message::TlsStarted{handle: self.handle.clone(), verify}).await {
					Ok(_) => (),
					// can only happen during shutdown, drop it.
					Err(_) => return,
				};
				sock.into()
			},
			None => {
				match MAIN_CHANNEL.send(Message::Connect{handle: self.handle.clone()}).await {
					Ok(_) => (),
					// can only happen during shutdown, drop it.
					Err(_) => return,
				};
				sock.into()
			}
		};
		StreamWorker::new(
			self.rx,
			conn,
			self.stream_cfg,
			self.handle,
		).spawn();
	}
}

impl Spawn for ConnectWorker {
	fn spawn(self) {
		tokio::spawn(async move { self.run().await });
	}
}
