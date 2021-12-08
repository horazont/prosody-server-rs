/*!
# Utilites for I/O via Tokio
*/
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration};

use pin_project_lite::pin_project;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use futures_util::stream::Stream;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::{timeout, Sleep, sleep, Instant};


pub trait AsyncReadable {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl AsyncReadable for TcpStream {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		TcpStream::poll_read_ready(self, cx)
	}
}

impl AsyncReadable for UnixStream {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		UnixStream::poll_read_ready(self, cx)
	}
}

impl<T: AsyncReadable> AsyncReadable for tokio_rustls::client::TlsStream<T> {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let (sock, tls) = self.get_mut();
		if tls.wants_read() {
			sock.poll_read_ready(cx)
		} else {
			Poll::Ready(Ok(()))
		}
	}
}

impl<T: AsyncReadable> AsyncReadable for tokio_rustls::server::TlsStream<T> {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let (sock, tls) = self.get_mut();
		if tls.wants_read() {
			sock.poll_read_ready(cx)
		} else {
			Poll::Ready(Ok(()))
		}
	}
}

impl<T: AsyncReadable> AsyncReadable for tokio_rustls::TlsStream<T> {
	fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let (sock, tls) = self.get_mut();
		if tls.wants_read() {
			sock.poll_read_ready(cx)
		} else {
			Poll::Ready(Ok(()))
		}
	}
}


/// Attempt an I/O operation, returning a timeout if it does not complete
/// within the given duration.
///
/// This is mere a shim wrapper around [`tokio::time::timeout`] which converts
/// the [`tokio::time::error::Elapsed`] into a [`std::io::Error`] of kind
/// [`std::io::ErrorKind::TimedOut`], with the given `msg` as error message.
#[inline]
pub(crate) async fn iotimeout<T, F: std::future::Future<Output = io::Result<T>>>(t: Duration, f: F, msg: &'static str) -> io::Result<T> {
	match timeout(t, f).await {
		Ok(r) => r,
		Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, msg)),
	}
}


pub trait TxBufRead {
	/// Return the current buffer if one is available, otherwise return None.
	///
	/// This must never block. If a buffer is temporarily not available, it should simply return None.
	///
	/// If no call to advance is made in between calls to get_buf, the same buffer MUST be returned.
	fn get_buf(&mut self) -> Option<&[u8]>;

	/// Consume the given amount of bytes.
	///
	/// Calling this with a value larger than the length of the buffer currently returned by get_buf causes a panic.
	fn advance(&mut self, by: usize);
}

impl<T: Buf> TxBufRead for VecDeque<T> {
	fn get_buf(&mut self) -> Option<&[u8]> {
		while let Some(buf) = self.front() {
			if buf.remaining() == 0 {
				self.pop_front();
			} else {
				break
			}
		}
		Some(self.front()?.chunk())
	}

	fn advance(&mut self, by: usize) {
		let buf = self.front_mut();
		match buf {
			Some(v) => {
				v.advance(by);
				if v.remaining() == 0 {
					self.pop_front();
				}
			},
			None => panic!("advance() without buffer"),
		}
	}
}


pin_project! {
	pub struct DuplexStream<I, T> {
		inner: I,
		txsrc: T,
		rxbuf: Option<BytesMut>,
		read_timeout: tokio::time::Duration,
		write_timeout: tokio::time::Duration,
		may_read: bool,
		may_write: bool,
		flush_needed: bool,
		#[pin]
		read_deadline: Sleep,
		#[pin]
		write_deadline: Sleep,
	}
}


impl<I, T> DuplexStream<I, T> where DuplexStream<I, T>: Stream {
	pub fn new(
			inner: I,
			txsrc: T,
			read_timeout: tokio::time::Duration,
			write_timeout: tokio::time::Duration,
	) -> Self {
		Self{
			inner,
			txsrc,
			rxbuf: None,
			may_read: true,
			may_write: true,
			flush_needed: false,
			read_timeout,
			write_timeout,
			read_deadline: sleep(read_timeout),
			write_deadline: sleep(write_timeout),
		}
	}

	pub fn into_inner(self) -> (I, T) {
		(self.inner, self.txsrc)
	}

	pub fn set_read_deadline(self: Pin<&mut Self>, deadline: Instant) {
		let this = self.project();
		this.read_deadline.reset(deadline);
	}

	pub fn set_write_deadline(self: Pin<&mut Self>, deadline: Instant) {
		let this = self.project();
		this.write_deadline.reset(deadline);
	}

	pub fn get_pin(self: Pin<&Self>) -> (&I, &T) {
		let this = self.project_ref();
		(this.inner, this.txsrc)
	}

	pub fn get_pin_mut(self: Pin<&mut Self>) -> (&mut I, &mut T) {
		let this = self.project();
		(this.inner, this.txsrc)
	}

	pub fn set_may_write(self: Pin<&mut Self>, may: bool) {
		let this = self.project();
		*this.may_write = may;
	}

	pub fn set_may_read(self: Pin<&mut Self>, may: bool) {
		let this = self.project();
		*this.may_read = may;
	}
}

#[derive(Debug)]
pub enum ReadResult {
	NoRead,
	Ok(Bytes),
	Err(io::Error),
	Eof,
}

#[derive(Debug)]
pub struct DuplexStreamItem {
	// Possible situations for a read:
	// - Some data read: return buffer
	// - Read failed: return io error
	// - Timeout triggered: return io::ErrorKind::TimedOut
	// - No data read (but call returned because a write error for instance): return None
	// - Read EOF
	pub read_result: ReadResult,

	// Possible situations for a write:
	// - Did not happen because no buffer
	// - Write timeout triggered: return io::ErrorKind::TimedOut
	// - Some bytes written, but there's still some data left in the buffer
	// - All bytes written, no more data in the buffer
	// - Write stuck pending
	// - Write or flush failed: return io error
	pub write_result: Result<(), io::Error>,
}

impl<I: AsyncRead + AsyncWrite + Unpin, T: TxBufRead> Stream for DuplexStream<I, T> {
	type Item = DuplexStreamItem;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		// This has three main tasks:
		// 1. Attempt a write if we've got anything to write
		// 2. Attempt a read
		// 3. Return if: something was read *or* something was written *or* a timeout triggered
		//
		// Effectively, we'll never return None though.
		assert!(self.may_read || self.may_write);

		let mut this = self.project();
		let now = tokio::time::Instant::now();

		let mut write_result = Ok(());
		if *this.may_write {
			let mut wrote_anything = false;
			let mut all_written = true;
			while let Some(txbuf) = this.txsrc.get_buf() {
				assert!(txbuf.len() > 0);
				match Pin::new(&mut this.inner).poll_write(cx, txbuf) {
					Poll::Ready(Ok(nbytes)) => {
						// TODO: account for written bytes maybe
						this.txsrc.advance(nbytes);
						// if the buffer is depleted, we will see that below during
						// the read poll, but we first try to read to make this fair.
						wrote_anything = true;
						*this.flush_needed = true;
					},
					Poll::Ready(Err(e)) => {
						write_result = Err(e);
						// write failed, let's exit
						all_written = false;
						break
					},
					Poll::Pending => {
						// if we cannot write right now, we still try to read and
						// exit the loop.
						all_written = false;
						break
					},
				}
			}
			if wrote_anything {
				// ensure to advance the write deadline
				this.write_deadline.as_mut().reset(now + *this.write_timeout);
			}
			if all_written && *this.flush_needed && write_result.is_ok() {
				match Pin::new(&mut this.inner).poll_flush(cx) {
					Poll::Ready(Ok(())) => {
						*this.flush_needed = false;
					},
					Poll::Ready(Err(e)) => {
						write_result = Err(e);
						// TODO: cancel flushing here?
					},
					Poll::Pending => (),
				}
			}
			// no error during write && nothing written && not all written -> problematic
			if !wrote_anything && !all_written && write_result.is_ok() {
				// no read result? check if we need to check the read timeout
				match this.write_deadline.poll(cx) {
					Poll::Ready(_) => {
						write_result = Err(io::Error::new(io::ErrorKind::TimedOut, "write timeout elapsed"));
					},
					_ => (),
				}
			}
		}

		let read_result = if *this.may_read {
			let rxbuf = this.rxbuf.get_or_insert_with(|| BytesMut::with_capacity(8192));
			let mut read_result = {
				let read_buf = this.inner.read_buf(rxbuf);
				tokio::pin!(read_buf);
				match read_buf.poll(cx) {
					Poll::Ready(Ok(n)) => {
						// advance read timeout
						this.read_deadline.as_mut().reset(now + *this.read_timeout);
						if n > 0 {
							ReadResult::Ok(this.rxbuf.take().unwrap().freeze())
						} else {
							ReadResult::Eof
						}
					},
					Poll::Ready(Err(e)) => ReadResult::Err(e),
					Poll::Pending => ReadResult::NoRead,
				}
			};

			if matches!(&read_result, &ReadResult::NoRead) {
				// no read result? check if we need to check the read timeout
				match this.read_deadline.poll(cx) {
					Poll::Ready(_) => {
						read_result = ReadResult::Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout elapsed"));
					},
					_ => (),
				}
			}
			read_result
		} else {
			ReadResult::NoRead
		};

		match (&read_result, write_result.as_ref()) {
			// anything failed, return immediately
			(ReadResult::Err(_), _) | (_, Err(_)) |
			// anything was read, return immediately
				(ReadResult::Ok(_), _) |
			// eof detected, return immediately
				(ReadResult::Eof, _)
			=> {
				Poll::Ready(Some(DuplexStreamItem{
					read_result,
					write_result,
				}))
			},
			// otherwise, no return
			_ => Poll::Pending,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;

	use std::task::{Waker, RawWaker, RawWakerVTable};

	use bytes::Bytes;

	use tokio::io::ReadBuf;

	struct IoPattern {
		clock: usize,
		num_pending: usize,
		num_blocks: usize,
		blocksize: usize,
		error: Option<(usize, io::ErrorKind, &'static str)>,
	}

	enum IoStep {
		Execute(usize),
		Block,
	}

	impl IoPattern {
		fn contiguous(io_size: usize) -> Self {
			Self{
				clock: 0,
				num_pending: 0,
				num_blocks: 1,
				blocksize: io_size,
				error: None,
			}
		}

		fn alternating(io_size: usize) -> Self {
			Self{
				clock: 0,
				num_pending: 1,
				num_blocks: 1,
				blocksize: io_size,
				error: None,
			}
		}

		fn duty_cycle(cycle_len: usize, duty: usize, io_size: usize) -> Self {
			let num_blocks = duty;
			let num_pending = cycle_len - num_blocks;
			Self{
				clock: 0,
				num_pending,
				num_blocks,
				blocksize: io_size,
				error: None,
			}
		}

		fn never() -> Self {
			Self{
				clock: 0,
				num_pending: usize::MAX,
				num_blocks: 0,
				blocksize: 0,
				error: None,
			}
		}

		fn error(k: io::ErrorKind, msg: &'static str) -> Self {
			Self{
				clock: 0,
				num_pending: 0,
				num_blocks: 0,
				blocksize: 0,
				error: None,
			}.with_error_at(0, k, msg)
		}

		fn rhythm_len(&self) -> usize {
			self.num_pending + self.num_blocks
		}

		fn may_error(&self) -> io::Result<()> {
			match self.error {
				None => Ok(()),
				Some((at, kind, msg)) => {
					if self.clock == at {
						Err(io::Error::new(kind, msg))
					} else {
						Ok(())
					}
				},
			}
		}

		fn advance(&mut self) -> io::Result<IoStep> {
			self.may_error()?;
			let curr = self.clock;
			self.clock = self.clock.checked_add(1).expect("clock overflow");
			let len = self.rhythm_len();
			let step = curr % len;
			if step >= self.num_pending {
				Ok(IoStep::Execute(self.blocksize))
			} else {
				Ok(IoStep::Block)
			}
		}

		fn make_writable(mut self) -> Self {
			self.clock = self.num_pending;
			self
		}

		fn with_error_at(mut self, at: usize, k: io::ErrorKind, msg: &'static str) -> Self {
			self.error = Some((at, k, msg));
			self
		}
	}

	pin_project! {
		struct ChunkedPendingReader<'a> {
			src: &'a [u8],
			at: usize,
			rhythm: IoPattern,
		}
	}

	impl<'a> ChunkedPendingReader<'a> {
		fn new(src: &'a [u8], rhythm: IoPattern) -> Self {
			Self{src, at: 0, rhythm}
		}
	}

	impl<'a> AsyncRead for ChunkedPendingReader<'a> {
		fn poll_read(
			self: Pin<&mut Self>,
			_: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<io::Result<()>> {
			let this = self.project();
			if *this.at >= this.src.len() {
				// zero sized read at eof
				return Poll::Ready(Ok(()))
			}

			match this.rhythm.advance() {
				Ok(IoStep::Block) => Poll::Pending,
				Ok(IoStep::Execute(sz)) => {
					let sz = sz.min(buf.remaining());
					let begin = *this.at;
					let end = (begin + sz).min(this.src.len());
					*this.at = end;
					buf.put_slice(&this.src[begin..end]);
					Poll::Ready(Ok(()))
				},
				Err(e) => Poll::Ready(Err(e)),
			}
		}
	}

	pin_project! {
		struct ChunkedPendingWriter<'a> {
			dst: &'a mut [u8],
			at: usize,
			rhythm: IoPattern,
		}
	}

	impl<'a> ChunkedPendingWriter<'a> {
		fn new(dst: &'a mut [u8], rhythm: IoPattern) -> Self {
			Self{dst, at: 0, rhythm}
		}
	}

	impl<'a> AsyncWrite for ChunkedPendingWriter<'a> {
		fn poll_write(
			self: Pin<&mut Self>,
			_: &mut Context<'_>,
			buf: &[u8],
		) -> Poll<io::Result<usize>> {
			let this = self.project();
			let remaining = match this.dst.len().checked_sub(*this.at) {
				// zero sized write at eof
				Some(0) | None => return Poll::Ready(Ok(0)),
				Some(v) => v,
			};

			match this.rhythm.advance() {
				Ok(IoStep::Block) => Poll::Pending,
				Ok(IoStep::Execute(sz)) => {
					let sz = sz.min(remaining).min(buf.len());
					let begin = *this.at;
					let end = begin + sz;
					*this.at = end;
					this.dst[begin..end].copy_from_slice(&buf[..sz]);
					Poll::Ready(Ok(sz))
				},
				Err(e) => Poll::Ready(Err(e)),
			}
		}

		fn poll_shutdown(
			self: Pin<&mut Self>,
			_: &mut Context<'_>,
		) -> Poll<io::Result<()>> {
			Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "not implemented")))
		}

		fn poll_flush(
			self: Pin<&mut Self>,
			_: &mut Context<'_>,
		) -> Poll<io::Result<()>> {
			Poll::Ready(Ok(()))
		}
	}

	pin_project! {
		struct ChunkedPendingPair<'a> {
			#[pin]
			r: ChunkedPendingReader<'a>,
			#[pin]
			w: ChunkedPendingWriter<'a>,
		}
	}

	impl<'a> AsyncRead for ChunkedPendingPair<'a> {
		fn poll_read(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<io::Result<()>> {
			self.project().r.poll_read(cx, buf)
		}
	}

	impl<'a> AsyncWrite for ChunkedPendingPair<'a> {
		fn poll_write(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
			buf: &[u8],
		) -> Poll<io::Result<usize>> {
			self.project().w.poll_write(cx, buf)
		}

		fn poll_shutdown(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<io::Result<()>> {
			self.project().w.poll_shutdown(cx)
		}

		fn poll_flush(
			self: Pin<&mut Self>,
			cx: &mut Context<'_>,
		) -> Poll<io::Result<()>> {
			self.project().w.poll_flush(cx)
		}
	}

	fn rw_clone(_: *const ()) -> RawWaker {
		RawWaker::new(
			std::ptr::null(),
			&VTABLE,
		)
	}

	fn rw_wake(_: *const ()) -> () {
	}

	fn rw_wake_by_ref(_: *const ()) -> () {
	}

	fn rw_drop(_: *const ()) -> () {
	}

	static SAMPLE_DATA: &[u8] = b"Foobar 2342! Hello world! Some random stuff!";
	static VTABLE: RawWakerVTable = RawWakerVTable::new(
		rw_clone,
		rw_wake,
		rw_wake_by_ref,
		rw_drop,
	);

	fn dummy_waker() -> Waker {
		unsafe {
			Waker::from_raw(RawWaker::new(
				std::ptr::null(),
				&VTABLE,
			))
		}
	}

	fn drive<T, F: Future<Output = T> + Unpin>(mut fut: F) -> T {
		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		for _ in 1..10000 {
			match Pin::new(&mut fut).poll(&mut ctx) {
				Poll::Pending => (),
				Poll::Ready(r) => return r,
			}
		}
		panic!("exceeded iteration count for future driver")
	}

	#[test]
	fn chunked_pending_reader_contiguous() {
		let mut src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::contiguous(1),
		);
		let mut dst = Vec::<u8>::new();
		let fut = Box::pin(tokio::io::copy(&mut src, &mut dst));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_pending_reader_alternating_3byte() {
		let mut src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::alternating(3),
		);
		let mut dst = Vec::<u8>::new();
		let fut = Box::pin(tokio::io::copy(&mut src, &mut dst));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_pending_reader_dutycycled_3byte() {
		let mut src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::duty_cycle(5, 2, 3),
		);
		let mut dst = Vec::<u8>::new();
		let fut = Box::pin(tokio::io::copy(&mut src, &mut dst));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_pending_writer_only_writes_as_many_bytes_as_allowed_by_rhythm() {
		let src = &SAMPLE_DATA[..];
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), src.len());
		let mut writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::contiguous(4),
		);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);

		match Pin::new(&mut writer).poll_write(
			&mut ctx,
			&src[..],
		) {
			Poll::Ready(Ok(sz)) => {
				assert_eq!(sz, 4);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		assert_eq!(&dst[..4], &src[..4]);
		assert_eq!(&dst[4..6], &[0u8, 0][..]);
	}

	#[test]
	fn chunked_pending_writer_contiguous() {
		let mut src = &SAMPLE_DATA[..];
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), src.len());
		let mut writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::contiguous(1),
		);
		let fut = Box::pin(tokio::io::copy(&mut src, &mut writer));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_pending_writer_alternating_3byte() {
		let mut src = &SAMPLE_DATA[..];
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), src.len());
		let mut writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::alternating(3),
		);
		let fut = Box::pin(tokio::io::copy(&mut src, &mut writer));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_pending_writer_dutycycled_3byte() {
		let mut src = &SAMPLE_DATA[..];
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), src.len());
		let mut writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::duty_cycle(5, 2, 3),
		);
		let fut = Box::pin(tokio::io::copy(&mut src, &mut writer));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	#[test]
	fn chunked_rw_pair_arythmic() {
		let mut src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::duty_cycle(6, 5, 2),
		);
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), SAMPLE_DATA.len());
		let mut writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::duty_cycle(5, 2, 3),
		);
		let fut = Box::pin(tokio::io::copy(&mut src, &mut writer));
		match drive(fut) {
			Ok(sz) => {
				assert_eq!(sz as usize, SAMPLE_DATA.len());
			},
			other => panic!("unexpected result: {:?}", other),
		}
		assert_eq!(&dst[..], &SAMPLE_DATA[..]);
	}

	mod duplex_stream {
		use super::*;

		use futures_util::stream::StreamExt;


		struct SingleTxBuf<T> {
			buf: Option<T>,
		}

		impl<T: Buf> SingleTxBuf<T> {
			fn new(buf: T) -> Self {
				Self{buf: Some(buf)}
			}

			fn get(&self) -> Option<&T> {
				self.buf.as_ref()
			}
		}

		impl<T: Buf> TxBufRead for SingleTxBuf<T> {
			fn get_buf(&mut self) -> Option<&[u8]> {
				let buf = self.buf.as_ref()?.chunk();
				if buf.len() > 0 {
					Some(buf)
				} else {
					None
				}
			}

			fn advance(&mut self, by: usize) {
				self.buf.as_mut().unwrap().advance(by)
			}
		}

		#[tokio::test]
		async fn duplex_io_reads_and_writes_in_single_call() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::contiguous(4),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				// need alternating here to make the second call pending
				IoPattern::alternating(4).make_writable(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Ready(Some(DuplexStreamItem{read_result, write_result})) => {
					match read_result {
						ReadResult::Ok(rxbuf) => {
							assert_eq!(&rxbuf[..], &SAMPLE_DATA[..4]);
						},
						other => panic!("unexpected read result: {:?}", other),
					};

					match write_result {
						Ok(()) => (),
						other => panic!("unexpected write result: {:?}", other),
					}
				},
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 2);
		}

		#[tokio::test]
		async fn duplex_io_does_not_write_if_prohibited() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::contiguous(4),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				// need alternating here to make the second call pending
				IoPattern::alternating(4).make_writable(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			fut.as_mut().set_may_write(false);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Ready(Some(DuplexStreamItem{read_result, write_result})) => {
					match read_result {
						ReadResult::Ok(rxbuf) => {
							assert_eq!(&rxbuf[..], &SAMPLE_DATA[..4]);
						},
						other => panic!("unexpected read result: {:?}", other),
					};

					match write_result {
						Ok(()) => (),
						other => panic!("unexpected write result: {:?}", other),
					}
				},
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 6);
		}

		#[tokio::test]
		async fn duplex_io_does_not_read_if_prohibited() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::contiguous(4),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				// need alternating here to make the second call pending
				IoPattern::alternating(4).make_writable(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			fut.as_mut().set_may_read(false);
			match fut.as_mut().poll_next(&mut ctx) {
				// pending, because writes are done in the background
				Poll::Pending => (),
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 2);
		}

		#[tokio::test]
		async fn duplex_io_returns_on_read_even_without_write() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::contiguous(4),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Ready(Some(DuplexStreamItem{read_result, write_result})) => {
					match read_result {
						ReadResult::Ok(rxbuf) => {
							assert_eq!(&rxbuf[..], &SAMPLE_DATA[..4]);
						},
						other => panic!("unexpected read result: {:?}", other),
					};

					match write_result {
						Ok(()) => (),
						other => panic!("unexpected write result: {:?}", other),
					}
				},
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 6);
		}

		#[tokio::test]
		async fn duplex_io_pending_if_both_are_pending_and_txbuf_non_empty_and_timeout_not_elapsed() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Pending => (),
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 6);
		}

		#[tokio::test]
		async fn duplex_io_pending_if_both_are_pending_and_txbuf_empty_and_timeout_not_elapsed() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b""));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Pending => (),
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 0);
		}

		#[tokio::test]
		async fn duplex_io_returns_write_error_without_read_immediately() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::error(io::ErrorKind::Other, "the error"),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Ready(Some(DuplexStreamItem{read_result, write_result})) => {
					match read_result {
						ReadResult::NoRead => (),
						other => panic!("unexpected read result: {:?}", other),
					};

					match write_result {
						Err(e) => {
							assert_eq!(e.kind(), io::ErrorKind::Other);
						},
						other => panic!("unexpected write result: {:?}", other),
					}
				},
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 6);
		}

		#[tokio::test]
		async fn duplex_io_returns_read_error_after_write() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::error(io::ErrorKind::Other, "the error"),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::alternating(4).make_writable(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let waker = dummy_waker();
			let mut ctx = Context::from_waker(&waker);
			let fut = DuplexStream::new(stream, txbuf, Duration::new(100, 0), Duration::new(100, 0));
			tokio::pin!(fut);
			match fut.as_mut().poll_next(&mut ctx) {
				Poll::Ready(Some(DuplexStreamItem{read_result, write_result})) => {
					match read_result {
						ReadResult::Err(e) => {
							assert_eq!(e.kind(), io::ErrorKind::Other);
						},
						other => panic!("unexpected read result: {:?}", other),
					};

					match write_result {
						Ok(()) => (),
						other => panic!("unexpected write result: {:?}", other),
					}
				},
				other => panic!("unexpected poll result: {:?}", other),
			}

			let txbuf = fut.as_ref().get_pin().1.get().unwrap();
			assert_eq!(txbuf.remaining(), 2);
		}

		#[tokio::test(start_paused = true)]
		async fn check_sleep_behaviour() {
			let t0 = Instant::now();
			sleep(Duration::new(10, 0)).await;
			let t1 = Instant::now();
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 10.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_returns_read_timeout_error_on_timeout() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(10, 0), Duration::new(20, 0));
			tokio::pin!(fut);
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.read_result {
				ReadResult::Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.write_result {
				Ok(()) => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 10.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_blocking_read_blocks_timeout() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(10, 0), Duration::new(20, 0));
			tokio::pin!(fut);
			fut.as_mut().set_may_read(false);
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.write_result {
				Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.read_result {
				ReadResult::NoRead => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 20.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_blocking_write_blocks_timeout() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(20, 0), Duration::new(10, 0));
			tokio::pin!(fut);
			fut.as_mut().set_may_write(false);
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.read_result {
				ReadResult::Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.write_result {
				Ok(()) => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 20.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_nothing_to_write_prevents_write_timeout() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b""));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(20, 0), Duration::new(10, 0));
			tokio::pin!(fut);
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.read_result {
				ReadResult::Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.write_result {
				Ok(()) => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 20.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_loops_read_timeout() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(10, 0), Duration::new(20, 0));
			tokio::pin!(fut);
			let _ = fut.next().await.unwrap();
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.read_result {
				ReadResult::Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.write_result {
				Ok(()) => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 10.0);
			assert!(dt.as_secs_f64() < 20.0);
		}

		#[tokio::test(start_paused = true)]
		async fn duplex_io_loops_advance_read_deadline() {
			let src = ChunkedPendingReader::new(
				&SAMPLE_DATA[..],
				IoPattern::never(),
			);
			let mut dst = [0u8; 44];
			assert_eq!(dst[..].len(), SAMPLE_DATA.len());
			let writer = ChunkedPendingWriter::new(
				&mut dst,
				IoPattern::never(),
			);

			let stream = ChunkedPendingPair{r: src, w: writer};

			let txbuf = SingleTxBuf::new(Bytes::from_static(b"foobar"));

			let t0 = Instant::now();
			let fut = DuplexStream::new(stream, txbuf, Duration::new(10, 0), Duration::new(20, 0));
			tokio::pin!(fut);
			let _ = fut.next().await.unwrap();
			// definitely after the write deadline
			fut.as_mut().set_read_deadline(Instant::now() + Duration::new(20, 0));
			let result = fut.next().await.unwrap();
			let t1 = Instant::now();
			match result.write_result {
				Err(e) => {
					assert_eq!(e.kind(), io::ErrorKind::TimedOut);
				},
				other => panic!("unexpected read result: {:?}", other),
			};
			match result.read_result {
				ReadResult::NoRead => (),
				other => panic!("unexpected write result: {:?}", other),
			};
			let dt = t1 - t0;
			println!("{:?}", dt);
			assert!(dt.as_secs_f64() >= 20.0);
			assert!(dt.as_secs_f64() < 25.0);
		}
	}
}


#[derive(Debug)]
struct LazyBuffer<F, B> {
	allocator: Option<F>,
	buffer: Option<B>,
}

impl<B: BufMut, F: FnOnce() -> B> LazyBuffer<F, B> {
	// not used *yet*
	#[allow(dead_code)]
	fn new(f: F) -> Self {
		Self{
			allocator: Some(f),
			buffer: None,
		}
	}

	fn get_mut(&mut self) -> &mut B {
		debug_assert!(!(self.allocator.is_none() && self.buffer.is_none()));
		debug_assert!(!(self.allocator.is_some() && self.buffer.is_some()));
		match self.buffer {
			Some(ref mut buf) => buf,
			None => {
				let buf = self.allocator.take().unwrap()();
				self.buffer = Some(buf);
				self.buffer.as_mut().unwrap()
			},
		}
	}

	fn take(&mut self) -> Option<B> {
		self.buffer.take()
	}
}


pin_project! {
	#[derive(Debug)]
	#[must_use = "futures do nothing unless you `.await` or poll them"]
	pub struct LazyAllocRead<'a, S, B, F> {
		stream: &'a mut S,
		buf: LazyBuffer<F, B>,
		#[pin]
		_pin: PhantomPinned,
	}
}

impl<'a, B: BufMut, F: FnOnce() -> B, S: AsyncRead + Unpin> LazyAllocRead<'a, S, B, F>
	where LazyAllocRead<'a, S, B, F>: Future
{
	// not used *yet*
	#[allow(dead_code)]
	fn new(stream: &'a mut S, f: F) -> Self {
		Self{
			stream,
			buf: LazyBuffer::new(f),
			_pin: PhantomPinned,
		}
	}
}

impl<'a, B: BufMut, F: FnOnce() -> B, S: AsyncReadable + AsyncRead + Unpin> Future for LazyAllocRead<'a, S, B, F> {
	type Output = io::Result<B>;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Self::Output> {
		let this = self.project();
		match this.stream.poll_read_ready(cx) {
			Poll::Ready(Ok(_)) => (),
			Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
			Poll::Pending => return Poll::Pending,
		};

		let mut buf = this.buf.get_mut();
		let read_buf = this.stream.read_buf(&mut buf);
		tokio::pin!(read_buf);
		match read_buf.poll(cx) {
			Poll::Ready(Ok(_)) => Poll::Ready(Ok(this.buf.take().unwrap())),
			Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
			Poll::Pending => return Poll::Pending,
		}
	}
}
