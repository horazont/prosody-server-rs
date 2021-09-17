use std::error;
use std::fmt;
use std::future::Future;
use std::mem::MaybeUninit;
use std::io;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pin_project_lite::pin_project;

use bytes::{Buf, BufMut};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{timeout, timeout_at};


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


/// Attempt an I/O operation, returning a timeout if it does not complete
/// until the given instant.
///
/// This is mere a shim wrapper around [`tokio::time::timeout_at`] which
/// converts the [`tokio::time::error::Elapsed`] into a [`std::io::Error`] of
/// kind [`std::io::ErrorKind::TimedOut`], with the given `msg` as error
/// message.
#[inline]
pub(crate) async fn iodeadline<T, F: std::future::Future<Output = io::Result<T>>>(t: Instant, f: F, msg: &'static str) -> io::Result<T> {
	match timeout_at(t.into(), f).await {
		Ok(r) => r,
		Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, msg)),
	}
}


/// Error encountered during a [`duplex`] operation.
#[derive(Debug)]
pub enum DuplexError {
	/// An I/O error during the read operation was encountered.
	Read(
		/// The error which was returned by `poll_read`.
		io::Error,
	),

	/// An I/O error during the write operation was encountered.
	Write(
		/// The error which was returned by `poll_write`.
		io::Error,
	),
}

impl fmt::Display for DuplexError {
	fn fmt<'f>(&self, f: &'f mut fmt::Formatter) -> fmt::Result {
		let nested = match self {
			Self::Read(ref e) => {
				f.write_str("read error: ")?;
				e
			},
			Self::Write(ref e) => {
				f.write_str("write error: ")?;
				e
			},
		};
		fmt::Display::fmt(nested, f)
	}
}

impl error::Error for DuplexError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Read(ref e) => Some(e),
			Self::Write(ref e) => Some(e),
		}
	}
}

/// Summary of a [`duplex`] operation.
///
/// Refer to the [documentation of `duplex`][`duplex`] for more details.
#[derive(Debug, Clone, Copy)]
pub enum DuplexResult {
	/// Indicates that both read and write operations completed successfully
	///
	/// *Note:* This does not necessarily mean that the write buffer has been
	/// completely transmitted.
	Duplex(usize, usize),

	/// Indicates that at lesat one write buffer has been fully written, but no read
	/// operation has completed.
	Written(usize),

	/// Indicates that one read operation completed, but no write operations.
	Read(usize),
}

impl DuplexResult {
	/// Return the number of bytes read, if a read has completed.
	pub fn nread(&self) -> Option<usize> {
		match self {
			Self::Read(nread) | Self::Duplex(nread, _) => Some(*nread),
			_ => None,
		}
	}

	/// Return the number of bytes written in total, if any write has
	/// completed.
	pub fn nwritten(&self) -> Option<usize> {
		match self {
			Self::Written(nwritten) | Self::Duplex(_, nwritten) => Some(*nwritten),
			_ => None,
		}
	}
}

pin_project! {
	/// Future returned by [`duplex`]
	///
	/// See [`duplex`] for more details.
	#[derive(Debug)]
	#[must_use = "futures do nothing unless you `.await` or poll them"]
	pub struct DuplexOp<'a, S, T, R> {
		stream: &'a mut S,
		rxbuf: &'a mut R,
		txbuf: &'a mut T,
		nwritten: usize,
		#[pin]
		_pin: PhantomPinned,
	}
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin, T: Buf, R: BufMut> Future for DuplexOp<'a, S, T, R> {
	type Output = Result<DuplexResult, DuplexError>;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Self::Output> {
		let mut this = self.project();


		// Then we first attempt to write some bytes to the output. We do this
		// as long as the poll returns ready and we have more bytes to write.
		while this.txbuf.has_remaining() {
			match Pin::new(&mut this.stream).poll_write(cx, this.txbuf.chunk()) {
				Poll::Ready(Ok(nbytes)) => {
					*this.nwritten += nbytes;
					this.txbuf.advance(nbytes);
					// if the buffer is depleted, we will see that below during
					// the read poll, but we first try to read to make this fair.
				},
				Poll::Ready(Err(e)) => return Poll::Ready(Err(DuplexError::Write(e))),
				Poll::Pending => {
					// if we cannot write right now, we still try to read and
					// exit the loop.
					break
				},
			}
		}

		// Now for the read attempt. This is trickier because we need to deal
		// with potentially uninitialized bytes in the rxbuf.
		// This is inspired by what tokio internally does with the ReadBuf
		// future (not to be confused with the ReadBuf struct we use here!).
		// It is re-written to avoid relying on implementation details of
		// bytes::UninitSlice.
		let n = {
			let dst = this.rxbuf.chunk_mut();
			let dst = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut MaybeUninit<u8>, dst.len()) };
			let mut buf = ReadBuf::uninit(dst);
			let ptr = buf.filled().as_ptr();
			match Pin::new(this.stream).poll_read(cx, &mut buf) {
				// continue evaluation
				Poll::Ready(Ok(())) => {
					// safeguard shamelessly stolen
					assert_eq!(ptr, buf.filled().as_ptr());
					Some(buf.filled().len())
				},
				// return errors immediately
				Poll::Ready(Err(e)) => return Poll::Ready(Err(DuplexError::Read(e))),
				// no bytes read
				Poll::Pending => {
					None
				}
			}
		};

		match n {
			Some(n) => {
				// safety: due to how ReadBuf::filled works, it is guaranteed
				// that n bytes have actually been initialized.
				unsafe { this.rxbuf.advance_mut(n) }

				// We received something, we let them know and return
				// successfully.
				if *this.nwritten > 0 {
					Poll::Ready(Ok(DuplexResult::Duplex(n, *this.nwritten)))
				} else {
					Poll::Ready(Ok(DuplexResult::Read(n)))
				}
			},
			None => {
				// We didn't read anything. We now need to return ready though
				// if and only if we have nothing more to write
				if this.txbuf.has_remaining() {
					// More stuff to write? -> Claim pending in order to allow
					// more nice full duplex I/O.
					Poll::Pending
				} else {
					// Nothing more to write? -> Exit now because the caller
					// may have more stuff to write for us.
					Poll::Ready(Ok(DuplexResult::Written(*this.nwritten)))
				}
			}
		}
	}
}

/// Perform a full-duplex I/O operation on a single object implementing both
/// AsyncRead and AsyncWrite.
///
/// Equivalent to:
///
/// ```ignore
/// async fn duplex(
///     stream: &mut impl AsyncRead + AsyncWrite + Unpin,
///     rxbuf: &mut impl BufMut,
///     txbuf: &mut impl Buf,
/// ) -> Result<DuplexResult, DuplexError>;
/// ```
///
/// This is a read primitive which performs writes in parallel. The future
/// completes when any of the following is true:
///
/// - The `txbuf` has been completely written
/// - A read (of any size, even zero-sized) completed
/// - An error occured while either reading or writing
///
/// On success, returns a [`DuplexResult`]. The result indicates which
/// operations completed and how many bytes were transferred. Specifically,
/// the [`DuplexResult::nread`] can be used to distinguish the situation where
/// a write completed without any read (it returns None) or when EOF has been
/// reached (it returns Some(0)).
///
/// On failure, the error encountered is returned, wrapped in a
/// [`DuplexError`] enum to allow distinguishing read- and write errors.
///
/// At EOF, the future completes immediately, after attempting a write.
pub fn duplex<'a, S: AsyncRead + AsyncWrite + Unpin, R: BufMut, T: Buf>(stream: &'a mut S, rxbuf: &'a mut R, txbuf: &'a mut T) -> DuplexOp<'a, S, T, R> {
	DuplexOp{
		stream,
		txbuf,
		rxbuf,
		nwritten: 0,
		_pin: PhantomPinned,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::task::{Waker, RawWaker, RawWakerVTable};

	use bytes::{Bytes, BytesMut};

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
		todo!();
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

	// now that we're reasonably certain that the test fixtures do their job,
	// let's test the actual duplex thing

	#[test]
	fn duplex_io_reads_and_writes_in_single_call() {
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

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Ok(DuplexResult::Duplex(r, w))) => {
				assert_eq!(r, 4);
				assert_eq!(txbuf.remaining(), 2);
				assert_eq!(w, 4);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(&dst[..4], b"foob");
		assert_eq!(rxbuf.remaining(), 4);
		assert_eq!(&rxbuf[..], &SAMPLE_DATA[..4]);
	}

	#[test]
	fn duplex_io_returns_when_txbuf_is_exhausted_even_without_reads() {
		let src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::never(),
		);
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), SAMPLE_DATA.len());
		let writer = ChunkedPendingWriter::new(
			&mut dst,
			// need alternating here to make the second call pending
			IoPattern::alternating(6).make_writable(),
		);

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Ok(DuplexResult::Written(w))) => {
				assert_eq!(w, 6);
				assert_eq!(txbuf.remaining(), 0);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(&dst[..6], b"foobar");
		assert_eq!(rxbuf.remaining(), 0);
	}

	#[test]
	fn duplex_io_returns_on_read_even_without_write() {
		let src = ChunkedPendingReader::new(
			&SAMPLE_DATA[..],
			IoPattern::contiguous(1),
		);
		let mut dst = [0u8; 44];
		assert_eq!(dst[..].len(), SAMPLE_DATA.len());
		let writer = ChunkedPendingWriter::new(
			&mut dst,
			IoPattern::never(),
		);

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Ok(DuplexResult::Read(r))) => {
				assert_eq!(r, 1);
				assert_eq!(txbuf.remaining(), 6);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(rxbuf.remaining(), 1);
		assert_eq!(&rxbuf[..], &SAMPLE_DATA[..1]);
	}

	#[test]
	fn duplex_io_pending_if_both_are_pending_and_txbuf_non_empty() {
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

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Pending => (),
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(rxbuf.remaining(), 0);
		assert_eq!(txbuf.remaining(), 6);
	}

	#[test]
	fn duplex_io_returns_with_zero_write_if_both_pending_and_txbuf_empty() {
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

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Ok(DuplexResult::Written(0))) => (),
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(rxbuf.remaining(), 0);
		assert_eq!(txbuf.remaining(), 0);
	}

	#[test]
	fn duplex_io_returns_write_error_without_read_immediately() {
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

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Err(DuplexError::Write(e))) => {
				assert_eq!(e.kind(), io::ErrorKind::Other);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(rxbuf.remaining(), 0);
		assert_eq!(txbuf.remaining(), 6);
	}

	#[test]
	fn duplex_io_returns_read_error_after_write() {
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

		let mut stream = ChunkedPendingPair{r: src, w: writer};

		let mut txbuf = Bytes::from_static(b"foobar");
		let mut rxbuf = BytesMut::with_capacity(10).limit(10);

		let waker = dummy_waker();
		let mut ctx = Context::from_waker(&waker);
		let mut fut = Box::pin(duplex(&mut stream, &mut rxbuf, &mut txbuf));
		match Pin::new(&mut fut).poll(&mut ctx) {
			Poll::Ready(Err(DuplexError::Read(e))) => {
				assert_eq!(e.kind(), io::ErrorKind::Other);
			},
			other => panic!("unexpected poll result: {:?}", other),
		}

		let rxbuf = rxbuf.into_inner();
		assert_eq!(rxbuf.remaining(), 0);
		assert_eq!(txbuf.remaining(), 2);
	}
}
