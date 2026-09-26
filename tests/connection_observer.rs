use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};
use wreq::{
    Client,
    connection_observer::{ConnectionEvent, ConnectionObserver},
    tls::{TlsInfo, TlsVersion},
};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nobserved";
const CERT: &[u8] = include_bytes!("support/server.cert");

#[derive(Debug)]
enum Event {
    Connected(
        u64,
        Option<SocketAddr>,
        Option<SocketAddr>,
        bool,
        Option<TlsVersion>,
    ),
    Read(u64, Vec<u8>),
    Write(u64, Vec<u8>),
    Eof(u64),
    Closed(u64),
    Unexpected(String),
}

#[derive(Default)]
struct Events(Mutex<Vec<Event>>);

impl ConnectionObserver for Events {
    fn observe(&self, event: ConnectionEvent<'_>) {
        let event = match event {
            ConnectionEvent::Connected {
                id,
                local_addr,
                remote_addr,
                http2,
                tls_version,
            } => Event::Connected(id, local_addr, remote_addr, http2, tls_version),
            ConnectionEvent::Read { id, bytes } => Event::Read(id, bytes.to_vec()),
            ConnectionEvent::Write { id, bytes } => Event::Write(id, bytes.to_vec()),
            ConnectionEvent::Eof { id } => Event::Eof(id),
            ConnectionEvent::Closed { id } => Event::Closed(id),
            event => Event::Unexpected(format!("{event:?}")),
        };
        self.0.lock().unwrap().push(event);
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Http,
    Https,
    Tunnel,
    HttpsTunnel,
    #[cfg(feature = "socks")]
    Socks,
}

async fn read_head(io: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192, "request head too large");
        head.push(io.read_u8().await.unwrap());
    }
    head
}

async fn serve(mut io: impl AsyncRead + AsyncWrite + Unpin) -> Vec<u8> {
    let mut requests = Vec::new();
    for path in ["/first", "/second"] {
        let head = read_head(&mut io).await;
        assert!(head.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
        requests.extend(head);
        io.write_all(RESPONSE).await.unwrap();
        io.flush().await.unwrap();
    }
    // Keep the transport open until the client closes it so TLS shutdown does not race a drop.
    assert_eq!(io.read(&mut [0]).await.unwrap(), 0);
    requests
}

async fn accept_tls<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    version: SslVersion,
    http2: bool,
) -> tokio_btls::SslStream<T> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate(&X509::from_der(CERT).unwrap())
        .unwrap();
    acceptor
        .set_private_key(&PKey::private_key_from_der(include_bytes!("support/server.key")).unwrap())
        .unwrap();
    acceptor.check_private_key().unwrap();
    acceptor.set_min_proto_version(Some(version)).unwrap();
    acceptor.set_max_proto_version(Some(version)).unwrap();
    if http2 {
        acceptor.set_alpn_select_callback(|_, protocols| {
            select_next_proto(b"\x02h2", protocols).ok_or(AlpnError::ALERT_FATAL)
        });
    }
    let ssl = Ssl::new(acceptor.build().context()).unwrap();
    let mut stream = tokio_btls::SslStream::new(ssl, io).unwrap();
    Pin::new(&mut stream).accept().await.unwrap();
    assert_eq!(stream.ssl().version2(), Some(version));
    stream
}

fn expected_version(version: SslVersion) -> TlsVersion {
    match version {
        SslVersion::TLS1_2 => TlsVersion::TLS_1_2,
        SslVersion::TLS1_3 => TlsVersion::TLS_1_3,
        _ => panic!("unexpected test TLS version"),
    }
}

async fn serve_transport(
    mut io: impl AsyncRead + AsyncWrite + Unpin,
    transport: Transport,
    version: SslVersion,
) -> Vec<u8> {
    match transport {
        Transport::Tunnel | Transport::HttpsTunnel => {
            let connect = read_head(&mut io).await;
            assert!(connect.starts_with(b"CONNECT observer.test:443 HTTP/1.1\r\n"));
            io.write_all(b"HTTP/1.1 200 Connection Established\r\nX-Proxy-Only: yes\r\n\r\n")
                .await
                .unwrap();
            io.flush().await.unwrap();
        }
        #[cfg(feature = "socks")]
        Transport::Socks => {
            let mut greeting = [0; 3];
            io.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            io.write_all(&[5, 0]).await.unwrap();
            io.flush().await.unwrap();
            let mut request = [0; 5];
            io.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3, 13]);
            let mut target = [0; 15];
            io.read_exact(&mut target).await.unwrap();
            assert_eq!(&target[..13], b"observer.test");
            assert_eq!(&target[13..], &443u16.to_be_bytes());
            io.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 1, 187])
                .await
                .unwrap();
            io.flush().await.unwrap();
        }
        _ => {}
    }
    if matches!(transport, Transport::Http) {
        serve(io).await
    } else {
        serve(accept_tls(io, version, false).await).await
    }
}

async fn check_observation(transport: Transport, verbose: bool) {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        for tls_info in [false, true] {
            check_connection(transport, verbose, version, tls_info).await;
        }
    }
}

async fn check_connection(
    transport: Transport,
    verbose: bool,
    version: SslVersion,
    tls_info: bool,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        let requests = if matches!(transport, Transport::HttpsTunnel) {
            // Different proxy and origin versions catch accidental reporting of the outer TLS.
            let proxy_version = if version == SslVersion::TLS1_2 {
                SslVersion::TLS1_3
            } else {
                SslVersion::TLS1_2
            };
            let stream = accept_tls(socket, proxy_version, false).await;
            serve_transport(stream, transport, version).await
        } else {
            serve_transport(socket, transport, version).await
        };
        (peer, requests)
    });

    let events = Arc::new(Events::default());
    let mut builder = Client::builder()
        .no_proxy()
        .http1_only()
        .tls_cert_verification(false)
        .tls_verify_hostname(false)
        .tls_info(tls_info)
        .timeout(Duration::from_secs(5))
        .connection_verbose(verbose)
        .connection_observer(events.clone());
    let base = match transport {
        Transport::Http => format!("http://{addr}"),
        Transport::Https => format!("https://{addr}"),
        Transport::Tunnel | Transport::HttpsTunnel => {
            let scheme = if matches!(transport, Transport::HttpsTunnel) {
                "https"
            } else {
                "http"
            };
            builder = builder.proxy(wreq::Proxy::https(format!("{scheme}://{addr}")).unwrap());
            "https://observer.test".to_owned()
        }
        #[cfg(feature = "socks")]
        Transport::Socks => {
            builder = builder.proxy(wreq::Proxy::all(format!("socks5h://{addr}")).unwrap());
            "https://observer.test".to_owned()
        }
    };
    let client = builder.build().unwrap();
    for path in ["/first", "/second"] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), wreq::StatusCode::OK);
        assert_eq!(response.remote_addr(), Some(addr));
        if tls_info && !matches!(transport, Transport::Http) {
            let info = response.extensions().get::<TlsInfo>().unwrap();
            assert_eq!(info.peer_certificate(), Some(CERT));
            assert_eq!(info.protocol_version(), Some(expected_version(version)));
        } else {
            assert!(response.extensions().get::<TlsInfo>().is_none());
        }
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"observed");
    }

    drop(client);
    let (peer, requests) = tokio::time::timeout(Duration::from_secs(5), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let events = events.0.lock().unwrap();
    let Some(Event::Connected(id, local, remote, http2, tls_version)) = events.first() else {
        panic!("expected Connected before I/O: {events:?}");
    };
    assert_eq!(*local, Some(peer));
    assert_eq!(*remote, Some(addr));
    assert!(!http2);
    assert_eq!(
        *tls_version,
        (!matches!(transport, Transport::Http)).then(|| expected_version(version))
    );

    let mut read = Vec::new();
    let mut written = Vec::new();
    for event in &events[1..] {
        match event {
            Event::Read(event_id, bytes) => {
                assert_eq!(event_id, id);
                read.extend_from_slice(bytes);
            }
            Event::Write(event_id, bytes) => {
                assert_eq!(event_id, id);
                written.extend_from_slice(bytes);
            }
            Event::Eof(event_id) | Event::Closed(event_id) => assert_eq!(event_id, id),
            Event::Connected(..) => panic!("expected both requests to reuse one connection"),
            Event::Unexpected(event) => panic!("unexpected event: {event}"),
        }
    }
    assert_eq!(written, requests);
    assert_eq!(read, RESPONSE.repeat(2));
}

#[tokio::test]
async fn observes_http_with_pooling() {
    check_observation(Transport::Http, false).await;
}

#[tokio::test]
async fn observes_https_plaintext_with_pooling() {
    check_observation(Transport::Https, false).await;
}

#[tokio::test]
async fn excludes_connect_tunnel_setup() {
    check_observation(Transport::Tunnel, false).await;
}

#[tokio::test]
async fn observes_https_with_verbose_logging() {
    check_observation(Transport::Https, true).await;
}

#[tokio::test]
async fn observes_origin_tls_through_https_proxy() {
    check_observation(Transport::HttpsTunnel, false).await;
}

#[cfg(feature = "socks")]
#[tokio::test]
async fn observes_origin_tls_through_socks_proxy() {
    check_observation(Transport::Socks, false).await;
}

#[tokio::test]
async fn observes_http2_tls_without_response_tls_info() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = accept_tls(socket, version, true).await;
            assert_eq!(
                stream.ssl().selected_alpn_protocol(),
                Some(b"h2".as_slice())
            );
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(|request| async move {
                        assert_eq!(request.version(), http::Version::HTTP_2);
                        Ok::<_, Infallible>(http::Response::new(wreq::Body::from("observed")))
                    }),
                )
                .await
                .unwrap();
        });
        let events = Arc::new(Events::default());
        let client = Client::builder()
            .no_proxy()
            .tls_cert_verification(false)
            .tls_verify_hostname(false)
            .tls_info(false)
            .timeout(Duration::from_secs(5))
            .connection_observer(events.clone())
            .build()
            .unwrap();
        let response = client.get(format!("https://{addr}/")).send().await.unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        assert!(response.extensions().get::<TlsInfo>().is_none());
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"observed");
        {
            let events = events.0.lock().unwrap();
            let Some(Event::Connected(_, _, _, http2, tls_version)) = events.first() else {
                panic!("expected Connected before I/O: {events:?}");
            };
            assert!(*http2);
            assert_eq!(*tls_version, Some(expected_version(version)));
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), tasks.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
