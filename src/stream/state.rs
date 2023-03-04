use std::fmt;
use std::sync::Arc;

use tokio_rustls::rustls;

use crate::tls;
use crate::verify;

use super::msg::ControlMessage;

/**
TLS context configuration.

This configuration is optional. At socket creation, a TLS context may be
provided by the caller. It is then stored within the stream state to allow to
later call starttls without explicitly providing a context.
*/
#[derive(Clone)]
pub(crate) enum PreTlsConfig {
	/// No configuration was provided during socket creation.
	None,

	/// A client-side TLS context was provided.
	ClientSide(
		/// The server name to connect to. This is mandatory in rustls.
		rustls::ServerName,
		/// The rustls client configuration.
		Arc<rustls::ClientConfig>,
		/// A handle on the verification recorder for use during the
		/// handshake.
		///
		/// This is used to provide verification information to Lua.
		Arc<verify::RecordingVerifier>,
	),

	/// A server-side TLS context was provided.
	ServerSide(
		/// The rustls server configuration.
		Arc<rustls::ServerConfig>,
		/// A handle on the verification recorder for use during the
		/// handshake.
		///
		/// This is used to provide verification information to Lua.
		Arc<verify::RecordingClientVerifier>,
	),
}

impl fmt::Debug for PreTlsConfig {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::None => write!(f, "PreTlsConfig::None"),
			Self::ClientSide(name, ..) => write!(f, "PreTlsConfig::ClientSide({:?})", name),
			Self::ServerSide(..) => write!(f, "PreTlsConfig::ServerSide(..)"),
		}
	}
}

/**
Represents an error during an attempt to mutate a [`StreamState`].
*/
#[derive(Debug, Clone, Copy)]
pub(crate) enum StateTransitionError {
	/// Attempt to confirm TLS when TLS is already established.
	TlsAlreadyConfirmed,

	/// Attempt to start TLS while TLS is currently being negotiated.
	TlsInProgress,

	/// Attempt to start TLS after TLS has already been established.
	TlsEstablished,

	/// Attempt to start TLS without a context.
	ContextRequired,

	/// Attempt to start TLS from the client side without a peer server name.
	PeerNameRequired,

	/// Attempt to execute an operation which requires a connection, but the
	/// socket is already disconnected or has not fully connected yet.
	NotConnected,

	/// The state transition panicked in the past and the socket is now in an
	/// indeterminate state.
	Failed,
}

impl fmt::Display for StateTransitionError {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::TlsAlreadyConfirmed => f.write_str("invalid operation: TLS already confirmed"),
			Self::TlsInProgress => f.write_str("invalid operation: TLS handshake in progress"),
			Self::TlsEstablished => f.write_str("invalid operation: TLS already established"),
			Self::ContextRequired => {
				f.write_str("incomplete config: cannot start TLS without a context")
			}
			Self::PeerNameRequired => {
				f.write_str("incomplete config: peer name required to initiate TLS")
			}
			Self::NotConnected => f.write_str("invalid state: not connected"),
			Self::Failed => f.write_str("connection handle poisoned"),
		}
	}
}

impl std::error::Error for StateTransitionError {}

/**
Describes the stream state.

This is used for orchestrating the Lua callbacks on state transitions and to
figure out which actions are currently allowed.
*/
#[derive(Debug, Clone)]
pub(crate) enum StreamState {
	/// The connection is not established yet.
	///
	/// Only for sockets created through addclient.
	Connecting(PreTlsConfig),

	/// The connection is established, no TLS has been negotiated yet.
	///
	/// Future TLS negotiation is possible based on a call to starttls and possible available state.
	Plain(PreTlsConfig),

	/// The TLS handshake has been started through starttls() or while establishing the connection.
	TlsHandshaking,

	/// The TLS handshake has completed.
	Tls { info: tls::Info },

	/// The connection has been closed either locally or remotely.
	Disconnected,

	/// The connection broke internally during a state change.
	Failed,
}

impl StreamState {
	/// Helper function to make stream transitions without unnecessary cloning
	/// of the state easier to implement.
	///
	/// **Note:** If `f` panics, the `StreamState` will be set to `Failed`.
	#[inline]
	fn transition_impl<T, F: FnOnce(Self) -> Result<(Self, T), (Self, StateTransitionError)>>(
		&mut self,
		f: F,
	) -> Result<T, StateTransitionError> {
		let mut tmp = Self::Failed;
		std::mem::swap(&mut tmp, self);
		let result = match f(tmp) {
			Ok((new, v)) => {
				tmp = new;
				Ok(v)
			}
			Err((new, err)) => {
				tmp = new;
				Err(err)
			}
		};
		std::mem::swap(&mut tmp, self);
		result
	}

	/// Confirm a successful connection.
	///
	/// This transitions from `Connecting` to `Plain`. If the stream is in any
	/// state other than `Connecting`, no transition takes place.
	///
	/// Returns true if a transition took place.
	pub(crate) fn connect<'l>(&mut self) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| match this {
			Self::Connecting(tls) => Ok((Self::Plain(tls), true)),
			_ => Ok((this, false)),
		})
	}

	/// Confirm a completed TLS handshake.
	///
	/// The `verify` value is stored in the state for later retrieval.
	///
	/// This may transition from `Connecting`, `TlsHandshaking` or `Plain` to
	/// the `Tls` state. If transitioning from `Connecting`, true is returned,
	/// otherwise false.
	///
	/// If the stream is in a state other than the ones mentioned above, an
	/// error is returned and no transition takes place.
	pub(crate) fn confirm_tls<'l>(
		&mut self,
		info: tls::Info,
	) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| match this {
			Self::TlsHandshaking | Self::Plain(..) => Ok((Self::Tls { info }, false)),
			Self::Connecting(..) => Ok((Self::Tls { info }, true)),
			Self::Disconnected => Err((this, StateTransitionError::NotConnected)),
			Self::Failed => Err((this, StateTransitionError::Failed)),
			Self::Tls { .. } => Err((this, StateTransitionError::TlsAlreadyConfirmed)),
		})
	}

	/// Mark a stream as disconnected.
	///
	/// This transitions from any state (including Failed!) to `Disconnected`
	/// state.
	///
	/// Returns true if the state was previously not `Disconnected`.
	pub(crate) fn disconnect<'l>(&mut self) -> Result<bool, StateTransitionError> {
		self.transition_impl(|this| match this {
			Self::Disconnected => Ok((this, false)),
			_ => Ok((Self::Disconnected, true)),
		})
	}

	/// Prepare a TLS negotiation.
	///
	/// `given_config` and `given_servername` are optional if and only if
	/// there is a non-None [`PreTlsConfig`] associated with the stream.
	/// Otherwise, they must form a proper TLS config.
	///
	/// If the stream is in any state except Plain, an error is returned.
	///
	/// Otherwise, the [`ControlMessage`] required to initiate or accept a TLS
	/// connection is returned and the state transitions to `TlsHandshaking`.
	pub(super) fn start_tls(
		&mut self,
		given_config: Option<&tls::TlsConfig>,
		given_servername: Option<rustls::ServerName>,
	) -> Result<ControlMessage, StateTransitionError> {
		self.transition_impl(|this| {
			let tls_config = match this {
				Self::TlsHandshaking => return Err((this, StateTransitionError::TlsInProgress)),
				Self::Tls { .. } => return Err((this, StateTransitionError::TlsEstablished)),
				Self::Failed => return Err((this, StateTransitionError::Failed)),
				Self::Connecting(_) | Self::Disconnected => {
					return Err((this, StateTransitionError::NotConnected))
				}
				Self::Plain(ref tls) => tls,
			};

			let msg = match tls_config {
				PreTlsConfig::None => match given_config {
					// We can only *accept* connections based on the given config, as we lack a target hostname
					Some(tls::TlsConfig::Client { cfg, recorder }) => match given_servername {
						Some(v) => {
							ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone())
						}
						None => return Err((this, StateTransitionError::PeerNameRequired)),
					},
					Some(tls::TlsConfig::Server { cfg, recorder, .. }) => {
						ControlMessage::AcceptTls(cfg.clone(), recorder.clone())
					}
					None => return Err((this, StateTransitionError::ContextRequired)),
				},
				PreTlsConfig::ServerSide(cfg, recorder) => match given_config {
					// We can only *accept* connections based on the given config, as we lack a target hostname
					Some(tls::TlsConfig::Client { cfg, recorder }) => match given_servername {
						Some(v) => {
							ControlMessage::ConnectTls(v.to_owned(), cfg.clone(), recorder.clone())
						}
						None => return Err((this, StateTransitionError::PeerNameRequired)),
					},
					Some(tls::TlsConfig::Server { cfg, recorder, .. }) => {
						ControlMessage::AcceptTls(cfg.clone(), recorder.clone())
					}
					None => ControlMessage::AcceptTls(cfg.clone(), recorder.clone()),
				},
				PreTlsConfig::ClientSide(name, cfg, recorder) => {
					let name = match given_servername {
						Some(name) => name.to_owned(),
						None => name.clone(),
					};
					match given_config {
						// We can only *accept* connections based on the given config, as we lack a target hostname
						Some(tls::TlsConfig::Client { cfg, recorder }) => {
							ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone())
						}
						Some(tls::TlsConfig::Server { cfg, recorder, .. }) => {
							ControlMessage::AcceptTls(cfg.clone(), recorder.clone())
						}
						None => ControlMessage::ConnectTls(name, cfg.clone(), recorder.clone()),
					}
				}
			};

			Ok((StreamState::TlsHandshaking, msg))
		})
	}
}
