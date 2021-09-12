use std::io;
use std::time::Duration;

use tokio::time::timeout;


#[inline]
pub(crate) async fn iotimeout<T, F: std::future::Future<Output = io::Result<T>>>(t: Duration, f: F, msg: &'static str) -> io::Result<T> {
	match timeout(t, f).await {
		Ok(r) => r,
		Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, msg)),
	}
}
