use std::sync::Arc;

use bytes::Bytes;

use tokio_rustls::rustls;

use webpki;

use crate::verify;


pub(super) enum SocketOption {
	KeepAlive(bool),
}

pub(super) enum ControlMessage {
	Close,
	BlockReads,
	BlockWrites,
	UnblockWrites,
	Write(Bytes),
	SetOption(SocketOption),
	AcceptTls(Arc<rustls::ServerConfig>),
	ConnectTls(webpki::DNSName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>),
}
