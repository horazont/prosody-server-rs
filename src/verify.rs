/*!
# Recording of verification results during TLS handshake
*/
use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use tokio::task_local;

use tokio_rustls::rustls;


#[derive(Debug, Clone)]
pub(crate) enum VerificationRecord {
	Unverified,
	Passed{cert: rustls::Certificate},
	Failed{err: rustls::Error},
}

impl Default for VerificationRecord {
	fn default() -> Self {
		Self::Unverified
	}
}

task_local! {
	// we use a ref cell to make things fail loudly if reentrant access is happening.
	static CURRENT_VERIFIER: RefCell<VerificationRecord>;
}

pub(crate) struct RecordingVerifier {
	inner: Arc<dyn rustls::client::ServerCertVerifier>,
	pub(crate) strict: bool,
}

impl RecordingVerifier {
	pub(crate) fn new(inner: Arc<dyn rustls::client::ServerCertVerifier>, strict: bool) -> Self {
		Self{inner, strict}
	}

	pub(crate) async fn scope<F: Future>(&self, f: F) -> (VerificationRecord, F::Output) {
		CURRENT_VERIFIER.scope(RefCell::new(VerificationRecord::default()), async move {
			let result = f.await;
			(CURRENT_VERIFIER.with(|x| { x.take() }), result)
		}).await
	}
}

impl rustls::client::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
		CURRENT_VERIFIER.with(|x| {
			let (record, result) = match self.inner.verify_server_cert(
				end_entity,
				intermediates,
				server_name,
				scts,
				ocsp_response,
				now,
			) {
				Ok(r) => {
					let cert = end_entity.clone();
					(VerificationRecord::Passed{cert}, Ok(r))
				},
				Err(e) => (VerificationRecord::Failed{err: e.clone()}, Err(e)),
			};
			*x.borrow_mut() = record;
			if self.strict {
				result
			} else {
				Ok(rustls::client::ServerCertVerified::assertion())
			}
		})
	}
}

pub(crate) struct RecordingClientVerifier {
	inner: Arc<dyn rustls::server::ClientCertVerifier>,
	pub(crate) strict: bool,
}

impl RecordingClientVerifier {
	pub(crate) fn new(inner: Arc<dyn rustls::server::ClientCertVerifier>, strict: bool) -> Self {
		Self{inner, strict}
	}

	pub(crate) async fn scope<F: Future>(&self, f: F) -> (VerificationRecord, F::Output) {
		CURRENT_VERIFIER.scope(RefCell::new(VerificationRecord::default()), async move {
			let result = f.await;
			(CURRENT_VERIFIER.with(|x| { x.take() }), result)
		}).await
	}
}

impl rustls::server::ClientCertVerifier for RecordingClientVerifier {
	fn client_auth_mandatory(&self) -> Option<bool> {
		match self.inner.client_auth_mandatory() {
			Some(mandatory) => Some(mandatory && !self.strict),
			None => None,
		}
	}

	fn offer_client_auth(&self) -> bool {
		self.inner.offer_client_auth()
	}

	fn client_auth_root_subjects(&self) -> Option<Vec<rustls::internal::msgs::base::PayloadU16>> {
		// We never tell the peer which certificates we accept ... Otherwise it would be an awfully long list in the general case.
		Some(Vec::new())
	}

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
		CURRENT_VERIFIER.with(|x| {
			let (record, result) = match self.inner.verify_client_cert(end_entity, intermediates, now) {
				Ok(r) => {
					let cert = end_entity.clone();
					(VerificationRecord::Passed{cert}, Ok(r))
				},
				Err(e) => (VerificationRecord::Failed{err: e.clone()}, Err(e)),
			};
			*x.borrow_mut() = record;
			if self.strict {
				result
			} else {
				Ok(rustls::server::ClientCertVerified::assertion())
			}
		})
	}
}
