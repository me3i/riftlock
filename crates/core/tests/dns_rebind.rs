//! Real DNS-rebinding proof over local UDP/TCP sockets. The fixture DNS server
//! answers `rebind.test` with a documentation address first and loopback on
//! every later query, reproducing the time-of-check/time-of-use flip without
//! contacting any external host.

use reqwest::dns::{Addrs, Name as ReqwestName, Resolve, Resolving};
use riftlock_core::{SafeResolve, ScopeGuard, ScopedClient};
use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const DNS_NAME: &str = "rebind.test";
const SAFE_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn encode_name(name: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad label"));
        }
        out.push(u8::try_from(label.len()).expect("label length"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

fn read_name(message: &[u8], offset: &mut usize) -> io::Result<String> {
    let mut labels = Vec::new();
    loop {
        let length = *message
            .get(*offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated name"))?;
        *offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compression not expected in query",
            ));
        }
        let end = *offset + usize::from(length);
        let label = message
            .get(*offset..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated label"))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        *offset = end;
    }
    Ok(labels.join("."))
}

/// Minimal authoritative server: echoes the question and answers A queries.
fn serve_one(socket: &UdpSocket, a_queries: &AtomicUsize) -> io::Result<()> {
    let mut query = [0_u8; 512];
    let (length, peer) = socket.recv_from(&mut query)?;
    let query = &query[..length];
    if query.len() < 12 {
        return Ok(());
    }
    let mut offset = 12;
    let name = read_name(query, &mut offset)?;
    let qtype = u16::from_be_bytes(
        query
            .get(offset..offset + 2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated type"))?
            .try_into()
            .expect("two bytes"),
    );
    let question_end = offset + 4;

    let matches = name.eq_ignore_ascii_case(DNS_NAME) && qtype == TYPE_A;
    let ip = if matches {
        if a_queries.fetch_add(1, Ordering::SeqCst) == 0 {
            SAFE_IP
        } else {
            Ipv4Addr::LOCALHOST
        }
    } else {
        Ipv4Addr::UNSPECIFIED
    };

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[..2]); // ID
    response.extend_from_slice(&0x8180_u16.to_be_bytes()); // QR, RD, RA, NOERROR
    response.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&u16::from(matches).to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&[0; 4]); // NSCOUNT, ARCOUNT
    response.extend_from_slice(&query[12..question_end]);
    if matches {
        response.extend_from_slice(&[0xc0, 0x0c]); // name pointer to QNAME
        response.extend_from_slice(&TYPE_A.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&0_u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
    }
    socket.send_to(&response, peer)?;
    Ok(())
}

fn parse_a_records(response: &[u8]) -> io::Result<Vec<SocketAddr>> {
    if response.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS reply",
        ));
    }
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    let mut offset = 12;
    for _ in 0..questions {
        read_name(response, &mut offset)?;
        offset += 4;
    }
    let mut addrs = Vec::new();
    for _ in 0..answers {
        let length = *response
            .get(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated answer"))?;
        if length & 0xc0 == 0xc0 {
            offset += 2;
        } else {
            read_name(response, &mut offset)?;
        }
        let rtype = u16::from_be_bytes(
            response
                .get(offset..offset + 2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated rtype"))?
                .try_into()
                .expect("two bytes"),
        );
        let class = u16::from_be_bytes(
            response
                .get(offset + 2..offset + 4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated class"))?
                .try_into()
                .expect("two bytes"),
        );
        let rdlength = u16::from_be_bytes(
            response
                .get(offset + 8..offset + 10)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated rdata"))?
                .try_into()
                .expect("two bytes"),
        );
        offset += 10;
        let rdata = response
            .get(offset..offset + usize::from(rdlength))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated rdata body"))?;
        if rtype == TYPE_A && class == CLASS_IN && rdata.len() == 4 {
            addrs.push(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                0,
            ));
        }
        offset += usize::from(rdlength);
    }
    Ok(addrs)
}

#[derive(Clone, Debug)]
struct RebindingResolve {
    server: SocketAddr,
}

impl Resolve for RebindingResolve {
    fn resolve(&self, name: ReqwestName) -> Resolving {
        let server = self.server;
        Box::pin(async move {
            let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            socket
                .connect(server)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            let mut query = Vec::new();
            query.extend_from_slice(&0x1234_u16.to_be_bytes());
            query.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
            query.extend_from_slice(&1_u16.to_be_bytes());
            query.extend_from_slice(&[0; 6]);
            query.extend_from_slice(
                &encode_name(name.as_str())
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
            );
            query.extend_from_slice(&TYPE_A.to_be_bytes());
            query.extend_from_slice(&CLASS_IN.to_be_bytes());
            socket
                .send(&query)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            let mut reply = [0_u8; 512];
            let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut reply))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS timeout"))?
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            let addrs = parse_a_records(&reply[..length])
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
            if addrs.is_empty() {
                return Err(
                    Box::new(io::Error::new(io::ErrorKind::NotFound, "no A records"))
                        as Box<dyn Error + Send + Sync>,
                );
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn spawn_dns_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind local DNS socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set DNS read timeout");
    let addr = socket.local_addr().expect("DNS socket address");
    let a_queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&a_queries);
    std::thread::spawn(move || while serve_one(&socket, &counter).is_ok() {});
    (addr, a_queries)
}

#[tokio::test]
async fn scoped_client_blocks_rebinding_while_plain_reqwest_reaches_local_listener() {
    let (dns, _a_queries) = spawn_dns_server();
    let resolver = Arc::new(RebindingResolve { server: dns });
    let production = ScopeGuard::new(&[]).expect("production guard");
    let scoped = ScopedClient::from_builder_with_resolver(
        reqwest::Client::builder().no_proxy(),
        SafeResolve::new(Arc::clone(&resolver) as Arc<dyn Resolve>, &production),
    )
    .expect("build scoped client");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind local HTTP listener");
    let listener_addr = listener.local_addr().expect("HTTP listener address");
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<usize>();
    let listener_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = accepted_tx.send(());
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request).await.unwrap_or(0);
            let _ = seen_tx.send(bytes_read);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    let first = scoped
        .lookup_host(DNS_NAME, listener_addr.port())
        .await
        .expect("first answer is the documentation address");
    assert_eq!(first[0].ip(), IpAddr::V4(SAFE_IP));

    let scoped_result = scoped
        .get(format!("http://{DNS_NAME}:{}/", listener_addr.port()))
        .send()
        .await;
    assert!(
        scoped_result.is_err(),
        "loopback rebinding must be rejected"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), seen_rx.recv())
            .await
            .is_err(),
        "the scoped request must send no bytes to the listener"
    );

    let plain = reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::clone(&resolver))
        .build()
        .expect("build unguarded control client");
    let control_response = plain
        .get(format!("http://{DNS_NAME}:{}/", listener_addr.port()))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .expect("plain reqwest follows the loopback DNS answer");
    assert_eq!(control_response.status(), reqwest::StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
        .await
        .expect("listener accepts control connection");
    let received = tokio::time::timeout(Duration::from_secs(2), seen_rx.recv())
        .await
        .expect("listener receives control request")
        .expect("listener stays active");
    assert!(received > 0, "control request should deliver HTTP bytes");

    listener_task.abort();
}

#[derive(Clone, Debug)]
struct StaticResolve(IpAddr);

impl Resolve for StaticResolve {
    fn resolve(&self, _name: ReqwestName) -> Resolving {
        let addr = SocketAddr::new(self.0, 0);
        Box::pin(async move { Ok(Box::new(std::iter::once(addr)) as Addrs) })
    }
}

#[tokio::test]
async fn production_guard_sends_zero_bytes_to_a_real_loopback_listener() {
    let production = ScopeGuard::new(&[]).expect("production guard");
    assert!(!production.allows_private());
    let scoped = ScopedClient::from_builder_with_resolver(
        reqwest::Client::builder().no_proxy(),
        SafeResolve::new(
            Arc::new(StaticResolve(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            &production,
        ),
    )
    .expect("build scoped client");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind local HTTP listener");
    let port = listener.local_addr().expect("address").port();
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<usize>();
    let listener_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0_u8; 2048];
            let bytes_read = stream.read(&mut request).await.unwrap_or(0);
            let _ = seen_tx.send(bytes_read);
        }
    });

    assert!(scoped.lookup_host("loopback.test", port).await.is_err());
    assert!(scoped
        .get(format!("http://loopback.test:{port}/"))
        .send()
        .await
        .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(150), seen_rx.recv())
            .await
            .is_err(),
        "production policy must not connect to the loopback listener"
    );

    listener_task.abort();
}
