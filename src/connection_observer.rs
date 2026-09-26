//! Plaintext transport observation, below the HTTP codec and above TLS.

use std::{io, net::SocketAddr};

use crate::tls::TlsVersion;

/// Receives connection events without enabling global tracing.
///
/// Callbacks run synchronously on the I/O task and must not block or panic. A shared observer
/// may receive concurrent callbacks from different connections. Within one connection, events
/// follow transport operation order. Borrowed bytes and errors are valid only during the call;
/// copy them to retain them. The observer never changes the bytes or transport result.
///
/// IDs distinguish connections within this process, not requests. Pooling, redirects, retries,
/// and HTTP/2 multiplexing can associate multiple exchanges with one observer. Proxy tunnel
/// setup and TLS handshakes occur below this hook and are not reported. Write events mean bytes
/// accepted by the plaintext stream, not acknowledgement by the remote peer.
///
/// These events may contain credentials and other secrets. They are not sent to tracing unless
/// verbose connection logging is independently enabled. Cancellation and request policy remain
/// the client's responsibility. Dropping a connection reports `Closed`, which is not an EOF.
/// A panic from that final callback is caught and discarded, so a drop during unwinding cannot
/// abort the process; panics from every other callback propagate to the I/O task.
pub trait ConnectionObserver: Send + Sync + 'static {
    /// Observe one transport event.
    fn observe(&self, event: ConnectionEvent<'_>);
}

/// One event from a plaintext connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectionEvent<'a> {
    /// The connection is ready, before any application bytes are transferred.
    Connected {
        /// Process-local connection identifier.
        id: u64,
        /// Local socket address, when available.
        local_addr: Option<SocketAddr>,
        /// Remote socket address, when available (possibly a proxy).
        remote_addr: Option<SocketAddr>,
        /// Whether TLS negotiated HTTP/2.
        http2: bool,
        /// Negotiated TLS version of the observed transport, when available.
        ///
        /// For CONNECT and SOCKS tunnels this describes TLS to the origin, not to the proxy.
        /// Available independently of [`ClientBuilder::tls_info`](crate::ClientBuilder::tls_info).
        /// Plaintext transports have no TLS version.
        tls_version: Option<TlsVersion>,
    },
    /// Newly read bytes; excludes any previously filled part of the read buffer.
    Read {
        /// Connection identifier.
        id: u64,
        /// Plaintext bytes.
        bytes: &'a [u8],
    },
    /// Successfully written bytes, including successful prefixes of vectored writes.
    Write {
        /// Connection identifier.
        id: u64,
        /// Plaintext bytes.
        bytes: &'a [u8],
    },
    /// A read with available buffer capacity returned no new bytes.
    Eof {
        /// Connection identifier.
        id: u64,
    },
    /// A transport read failed. Request-level timeouts need not produce this event.
    ReadError {
        /// Connection identifier.
        id: u64,
        /// The transport error.
        error: &'a io::Error,
    },
    /// A transport write failed, including a vectored write.
    WriteError {
        /// Connection identifier.
        id: u64,
        /// The transport error.
        error: &'a io::Error,
    },
    /// Flushing the transport failed.
    FlushError {
        /// Connection identifier.
        id: u64,
        /// The transport error.
        error: &'a io::Error,
    },
    /// Shutting down the transport's write side failed.
    ShutdownError {
        /// Connection identifier.
        id: u64,
        /// The transport error.
        error: &'a io::Error,
    },
    /// The transport wrapper was dropped, including cancellation and local disposal.
    Closed {
        /// Connection identifier.
        id: u64,
    },
}
