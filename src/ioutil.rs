use std::io;
use std::time::Duration;

use tokio::time::timeout;
use tokio::time::error::Elapsed;


#[inline]
pub(crate) fn flatten_timeout<T>(r: Result<Result<T, io::Error>, Elapsed>, msg: &'static str) -> Result<T, io::Error> {
	match r {
		Ok(r) => r,
		Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, msg)),
	}
}

#[inline]
pub(crate) async fn flattened_timeout<T, F: std::future::Future<Output = io::Result<T>>>(t: Duration, f: F, msg: &'static str) -> io::Result<T> {
	flatten_timeout(timeout(t, f).await, msg)
}
