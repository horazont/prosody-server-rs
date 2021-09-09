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
				Ok(_) => {
					let cert = presented_certs[0].clone();
					(VerificationRecord::Passed{cert}, Ok(rustls::ServerCertVerified::assertion()))
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
