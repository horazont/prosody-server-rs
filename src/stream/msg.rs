use std::sync::Arc;

use bytes::Bytes;

use tokio_rustls::rustls;

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
	AcceptTls(Arc<rustls::ServerConfig>, Arc<verify::RecordingClientVerifier>),
	ConnectTls(rustls::ServerName, Arc<rustls::ClientConfig>, Arc<verify::RecordingVerifier>),
}
