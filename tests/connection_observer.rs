use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::X509,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};
use wreq::{
    Client,
    connection_observer::{ConnectionEvent, ConnectionObserver},
    tls::TlsInfo,
};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nobserved";
const CERT: &[u8] = include_bytes!("support/server.cert");

#[derive(Debug)]
enum Event {
    Connected(u64, Option<SocketAddr>, Option<SocketAddr>, bool),
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
            } => Event::Connected(id, local_addr, remote_addr, http2),
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

async fn check_observation(transport: Transport, verbose: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (mut socket, peer) = listener.accept().await.unwrap();
        if matches!(transport, Transport::Tunnel) {
            let connect = read_head(&mut socket).await;
            assert!(connect.starts_with(b"CONNECT observer.test:443 HTTP/1.1\r\n"));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\nX-Proxy-Only: yes\r\n\r\n")
                .await
                .unwrap();
        }

        let requests = if matches!(transport, Transport::Http) {
            serve(socket).await
        } else {
            let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate(&X509::from_der(CERT).unwrap())
                .unwrap();
            acceptor
                .set_private_key(
                    &PKey::private_key_from_der(include_bytes!("support/server.key")).unwrap(),
                )
                .unwrap();
            acceptor.check_private_key().unwrap();
            let ssl = Ssl::new(acceptor.build().context()).unwrap();
            let mut stream = tokio_btls::SslStream::new(ssl, socket).unwrap();
            Pin::new(&mut stream).accept().await.unwrap();
            serve(stream).await
        };
        (peer, requests)
    });

    let events = Arc::new(Events::default());
    let mut builder = Client::builder()
        .no_proxy()
        .http1_only()
        .tls_cert_verification(false)
        .tls_verify_hostname(false)
        .tls_info(true)
        .timeout(Duration::from_secs(5))
        .connection_verbose(verbose)
        .connection_observer(events.clone());
    let base = match transport {
        Transport::Http => format!("http://{addr}"),
        Transport::Https => format!("https://{addr}"),
        Transport::Tunnel => {
            builder = builder.proxy(wreq::Proxy::https(format!("http://{addr}")).unwrap());
            "https://observer.test".to_owned()
        }
    };
    let client = builder.build().unwrap();
    for path in ["/first", "/second"] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), wreq::StatusCode::OK);
        assert_eq!(response.remote_addr(), Some(addr));
        if !matches!(transport, Transport::Http) {
            assert_eq!(
                response
                    .extensions()
                    .get::<TlsInfo>()
                    .unwrap()
                    .peer_certificate(),
                Some(CERT)
            );
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
    let Some(Event::Connected(id, local, remote, http2)) = events.first() else {
        panic!("expected Connected before I/O: {events:?}");
    };
    assert_eq!(*local, Some(peer));
    assert_eq!(*remote, Some(addr));
    assert!(!http2);

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
