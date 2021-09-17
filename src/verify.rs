use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use tokio::task_local;

use tokio_rustls::rustls;

use webpki;


#[derive(Debug, Clone)]
pub(crate) enum VerificationRecord {
	Unverified,
	Passed{cert: rustls::Certificate},
	Failed{err: rustls::TLSError},
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
	inner: Arc<dyn rustls::ServerCertVerifier>,
	pub(crate) strict: bool,
}

impl RecordingVerifier {
	pub(crate) fn new(inner: Arc<dyn rustls::ServerCertVerifier>, strict: bool) -> Self {
		Self{inner, strict}
	}

	pub(crate) async fn scope<F: Future>(&self, f: F) -> (VerificationRecord, F::Output) {
		CURRENT_VERIFIER.scope(RefCell::new(VerificationRecord::default()), async move {
			let result = f.await;
			(CURRENT_VERIFIER.with(|x| { x.take() }), result)
		}).await
	}
}

impl rustls::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        roots: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        dns_name: webpki::DNSNameRef<'_>,
        ocsp_response: &[u8]
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		CURRENT_VERIFIER.with(|x| {
			let (record, result) = match self.inner.verify_server_cert(roots, presented_certs, dns_name, ocsp_response) {
				Ok(r) => {
					let cert = presented_certs[0].clone();
					(VerificationRecord::Passed{cert}, Ok(r))
				},
				Err(e) => (VerificationRecord::Failed{err: e.clone()}, Err(e)),
			};
			*x.borrow_mut() = record;
			if self.strict {
				result
			} else {
				Ok(rustls::ServerCertVerified::assertion())
			}
		})
	}
}

pub(crate) struct RecordingClientVerifier {
	inner: Arc<dyn rustls::ClientCertVerifier>,
	pub(crate) strict: bool,
}

impl RecordingClientVerifier {
	pub(crate) fn new(inner: Arc<dyn rustls::ClientCertVerifier>, strict: bool) -> Self {
		Self{inner, strict}
	}

	pub(crate) async fn scope<F: Future>(&self, f: F) -> (VerificationRecord, F::Output) {
		CURRENT_VERIFIER.scope(RefCell::new(VerificationRecord::default()), async move {
			let result = f.await;
			(CURRENT_VERIFIER.with(|x| { x.take() }), result)
		}).await
	}
}

impl rustls::ClientCertVerifier for RecordingClientVerifier {
	fn client_auth_mandatory(&self, sni: Option<&webpki::DNSName>) -> Option<bool> {
		match self.inner.client_auth_mandatory(sni) {
			Some(mandatory) => Some(mandatory && !self.strict),
			None => None,
		}
	}

	fn offer_client_auth(&self) -> bool {
		self.inner.offer_client_auth()
	}

	fn client_auth_root_subjects(&self, sni: Option<&webpki::DNSName>) -> Option<Vec<rustls::internal::msgs::base::PayloadU16>> {
		self.inner.client_auth_root_subjects(sni)
	}

    fn verify_client_cert(
        &self,
        presented_certs: &[rustls::Certificate],
        sni: Option<&webpki::DNSName>,
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
		CURRENT_VERIFIER.with(|x| {
			let (record, result) = match self.inner.verify_client_cert(presented_certs, sni) {
				Ok(r) => {
					let cert = presented_certs[0].clone();
					(VerificationRecord::Passed{cert}, Ok(r))
				},
				Err(e) => (VerificationRecord::Failed{err: e.clone()}, Err(e)),
			};
			*x.borrow_mut() = record;
			if self.strict {
				result
			} else {
				Ok(rustls::ClientCertVerified::assertion())
			}
		})
	}
}
