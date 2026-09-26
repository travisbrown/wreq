//! Plaintext transport observation, below the HTTP codec and above TLS.
//!
//! This layer is independent of [`super::verbose`] tracing. It is installed only when a client
//! sets [`ClientBuilder::connection_observer`](crate::ClientBuilder::connection_observer), and
//! adds no per-I/O overhead when unset: no observation wrapper is installed.

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Connected, Connection, TlsInfoFactory, http::HttpInfo};
use crate::{
    connection_observer::{ConnectionEvent, ConnectionObserver},
    tls::TlsInfo,
};

/// Identifies connections within this process. Independent of the random identifiers that
/// verbose tracing gives its own log lines.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A transport wrapper that reports plaintext I/O to a [`ConnectionObserver`].
pub(super) struct Observed<T> {
    id: u64,
    inner: T,
    observer: Arc<dyn ConnectionObserver>,
}

impl<T: Connection + TlsInfoFactory> Observed<T> {
    /// Wrap a connected transport, reporting [`ConnectionEvent::Connected`] before any
    /// application bytes are transferred.
    pub(super) fn new(inner: T, observer: Arc<dyn ConnectionObserver>) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let connected = inner.connected();
        // Addresses are read the same way `Response::remote_addr` reads them, from the
        // `HttpInfo` extra that the TCP connectors attach. Absent that extra they are unknown.
        let mut extensions = http::Extensions::new();
        connected.set_extras(&mut extensions);
        let info = extensions.get::<HttpInfo>();
        observer.observe(ConnectionEvent::Connected {
            id,
            local_addr: info.map(HttpInfo::local_addr),
            remote_addr: info.map(HttpInfo::remote_addr),
            http2: connected.is_negotiated_h2(),
            tls_version: inner.tls_info().and_then(|info| info.protocol_version()),
        });

        Self {
            id,
            inner,
            observer,
        }
    }
}

impl<T> Observed<T> {
    fn observe(&self, event: ConnectionEvent<'_>) {
        self.observer.observe(event);
    }
}

impl<T> Drop for Observed<T> {
    fn drop(&mut self) {
        // Observers are documented not to panic, but one that does must not turn a drop during
        // unwinding into a process abort.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.observe(ConnectionEvent::Closed { id: self.id });
        }));
    }
}

impl<T: Connection + AsyncRead + AsyncWrite + Unpin> Connection for Observed<T> {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Observed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled = buf.filled().len();
        let had_capacity = buf.remaining() != 0;
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // A reader that shrinks the filled region violates the `AsyncRead` contract;
                // report nothing rather than panicking on the I/O task.
                let bytes = buf.filled().get(filled..).unwrap_or_default();
                if bytes.is_empty() {
                    if had_capacity {
                        self.observe(ConnectionEvent::Eof { id: self.id });
                    }
                } else {
                    self.observe(ConnectionEvent::Read { id: self.id, bytes });
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.observe(ConnectionEvent::ReadError {
                    id: self.id,
                    error: &error,
                });
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Observed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written != 0 {
                    self.observe(ConnectionEvent::Write {
                        id: self.id,
                        bytes: &buf[..written],
                    });
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.observe(ConnectionEvent::WriteError {
                    id: self.id,
                    error: &error,
                });
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(written)) => {
                // Report only the accepted prefix, one event per contributing slice.
                let mut left = written;
                for buf in bufs {
                    if left == 0 {
                        break;
                    }
                    let taken = left.min(buf.len());
                    if taken != 0 {
                        self.observe(ConnectionEvent::Write {
                            id: self.id,
                            bytes: &buf[..taken],
                        });
                    }
                    left -= taken;
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.observe(ConnectionEvent::WriteError {
                    id: self.id,
                    error: &error,
                });
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                self.observe(ConnectionEvent::FlushError {
                    id: self.id,
                    error: &error,
                });
                Poll::Ready(Err(error))
            }
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => {
                self.observe(ConnectionEvent::ShutdownError {
                    id: self.id,
                    error: &error,
                });
                Poll::Ready(Err(error))
            }
            other => other,
        }
    }
}

impl<T: TlsInfoFactory> TlsInfoFactory for Observed<T> {
    fn tls_info(&self) -> Option<TlsInfo> {
        self.inner.tls_info()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::AsyncWriteExt;

    use super::{
        super::{Connected, Connection, TlsInfoFactory},
        *,
    };

    #[derive(Default)]
    struct Events(Mutex<Vec<(&'static str, Vec<u8>)>>);

    impl ConnectionObserver for Events {
        fn observe(&self, event: ConnectionEvent<'_>) {
            let item = match event {
                ConnectionEvent::Connected { .. } => ("connected", vec![]),
                ConnectionEvent::Read { bytes, .. } => ("read", bytes.to_vec()),
                ConnectionEvent::Write { bytes, .. } => ("write", bytes.to_vec()),
                ConnectionEvent::Eof { .. } => ("eof", vec![]),
                ConnectionEvent::ReadError { .. } => ("error", vec![]),
                ConnectionEvent::WriteError { error, .. } => {
                    ("write_error", error.to_string().into_bytes())
                }
                ConnectionEvent::FlushError { error, .. } => {
                    ("flush_error", error.to_string().into_bytes())
                }
                ConnectionEvent::ShutdownError { error, .. } => {
                    ("shutdown_error", error.to_string().into_bytes())
                }
                ConnectionEvent::Closed { .. } => ("closed", vec![]),
            };
            self.0.lock().unwrap().push(item);
        }
    }

    struct Stream {
        read: usize,
    }

    impl Connection for Stream {
        fn connected(&self) -> Connected {
            Connected::new()
        }
    }

    impl TlsInfoFactory for Stream {
        fn tls_info(&self) -> Option<TlsInfo> {
            None
        }
    }

    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            self.read += 1;
            match self.read {
                1 => Poll::Pending,
                2 => {
                    buf.put_slice(b"new");
                    Poll::Ready(Ok(()))
                }
                3 => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                _ => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len().min(3)))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes
                .iter()
                .map(|slice| slice.len())
                .sum::<usize>()
                .min(3)))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn observes_only_new_and_successful_bytes() {
        let events = Arc::new(Events::default());
        let mut io = Observed::new(Stream { read: 0 }, events.clone());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut storage = [0; 16];
        let mut buf = ReadBuf::new(&mut storage);

        // Bytes already in the buffer belong to an earlier read and are not reported again.
        buf.put_slice(b"old");
        assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"oldnew");
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Err(_))
        ));
        // No capacity means no new bytes were requested, so this is not an EOF.
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut ReadBuf::new(&mut [])),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));

        assert_eq!(io.write(b"12345").await.unwrap(), 3);
        assert_eq!(
            io.write_vectored(&[IoSlice::new(b"ab"), IoSlice::new(b"cdef")])
                .await
                .unwrap(),
            3
        );
        io.flush().await.unwrap();
        io.shutdown().await.unwrap();
        drop(io);

        assert_eq!(
            *events.0.lock().unwrap(),
            vec![
                ("connected", vec![]),
                ("read", b"new".to_vec()),
                ("error", vec![]),
                ("eof", vec![]),
                ("write", b"123".to_vec()),
                ("write", b"ab".to_vec()),
                ("write", b"c".to_vec()),
                ("closed", vec![]),
            ]
        );
    }

    #[test]
    fn observes_write_side_errors_without_changing_them() {
        #[derive(Default)]
        struct FailingStream {
            pending: bool,
        }

        impl FailingStream {
            fn fail<T>(
                &mut self,
                cx: &mut Context<'_>,
                operation: &'static str,
            ) -> Poll<io::Result<T>> {
                self.pending = !self.pending;
                if self.pending {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, operation)))
                }
            }
        }

        impl Connection for FailingStream {
            fn connected(&self) -> Connected {
                Connected::new()
            }
        }

        impl TlsInfoFactory for FailingStream {}

        impl AsyncRead for FailingStream {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }

        impl AsyncWrite for FailingStream {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.fail(cx, "write")
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                _: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                self.fail(cx, "write_vectored")
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.fail(cx, "flush")
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                self.fail(cx, "shutdown")
            }
        }

        fn check_error<T>(
            mut poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
            events: &Events,
            operation: &str,
        ) {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let count = events.0.lock().unwrap().len();
            assert!(poll(&mut cx).is_pending());
            assert_eq!(events.0.lock().unwrap().len(), count);
            let Poll::Ready(Err(error)) = poll(&mut cx) else {
                panic!("expected {operation} to fail");
            };
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), operation);
        }

        let events = Arc::new(Events::default());
        let mut io = Observed::new(FailingStream::default(), events.clone());
        check_error(
            |cx| Pin::new(&mut io).poll_write(cx, b"data"),
            &events,
            "write",
        );
        check_error(
            |cx| Pin::new(&mut io).poll_write_vectored(cx, &[IoSlice::new(b"data")]),
            &events,
            "write_vectored",
        );
        check_error(|cx| Pin::new(&mut io).poll_flush(cx), &events, "flush");
        check_error(
            |cx| Pin::new(&mut io).poll_shutdown(cx),
            &events,
            "shutdown",
        );
        drop(io);

        assert_eq!(
            *events.0.lock().unwrap(),
            vec![
                ("connected", vec![]),
                ("write_error", b"write".to_vec()),
                ("write_error", b"write_vectored".to_vec()),
                ("flush_error", b"flush".to_vec()),
                ("shutdown_error", b"shutdown".to_vec()),
                ("closed", vec![]),
            ]
        );
    }

    #[test]
    fn a_panicking_observer_does_not_escalate_a_drop() {
        struct Panicking;
        impl ConnectionObserver for Panicking {
            fn observe(&self, event: ConnectionEvent<'_>) {
                assert!(
                    !matches!(event, ConnectionEvent::Closed { .. }),
                    "observer panic on close"
                );
            }
        }

        let io = Observed::new(Stream { read: 0 }, Arc::new(Panicking));
        drop(io);

        let panic = std::panic::catch_unwind(|| {
            let _io = Observed::new(Stream { read: 0 }, Arc::new(Panicking));
            panic!("original panic");
        })
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"original panic"));
    }
}
