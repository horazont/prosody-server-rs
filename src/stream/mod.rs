/*!
# Stream connection implementation

This module provides a handle/worker pair for a stream-based network
connection. In general, this will be a TCP connection, but it may also be a
Unix stream. However, any object implementing AsyncRead + AsyncWrite can be
used.

Related modules:

- [`crate::conn`] which handles creating stream connections either via a
  connect call from Lua or by wrapping existing sockets.
- [`crate::server`] which handles listening sockets.
*/

mod state;
mod msg;
mod worker;
mod connect;
mod handle;
mod lua;

pub(crate) use state::{
	StateTransitionError,
};

pub(crate) use handle::{
	StreamHandle,
};

pub(crate) use lua::{
	get_listeners,
	addclient,
	wrapclient,
};
