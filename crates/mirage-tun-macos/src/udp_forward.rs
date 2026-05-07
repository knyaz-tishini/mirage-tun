use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use mirage_tcpip_stack::udp::UdpMsg;
use tracing::{debug, warn};

const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct UdpSocks5Session {
    pub fwd_tx: mpsc::Sender<Vec<u8>>,
}

pub type UdpProxySessionMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpSocks5Session>>>;

/// Forward one UDP datagram through SOCKS5 UDP ASSOCIATE.
/// Creates a new session if none exists for (src_addr, dst_addr).
pub async fn udp_proxy_forward(
    payload: Vec<u8>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    resp_tx: mpsc::UnboundedSender<UdpMsg>,
    sessions: UdpProxySessionMap,
    socks5_addr: SocketAddr,
) {
    {
        let map = sessions.lock().await;
        if let Some(session) = map.get(&(src_addr, dst_addr)) {
            let _ = session.fwd_tx.try_send(payload);
            return;
        }
    }

    let (fwd_tx, fwd_rx) = mpsc::channel::<Vec<u8>>(64);
    {
        let mut map = sessions.lock().await;
        map.insert((src_addr, dst_addr), UdpSocks5Session { fwd_tx: fwd_tx.clone() });
    }
    let _ = fwd_tx.try_send(payload);

    let sessions2 = sessions.clone();
    tokio::spawn(async move {
        if let Err(e) = udp_proxy_session_task(
            src_addr, dst_addr, socks5_addr,
            fwd_rx, resp_tx,
        ).await {
            debug!("UDP proxy session {src_addr}→{dst_addr} ended: {e}");
        }
        sessions2.lock().await.remove(&(src_addr, dst_addr));
    });
}

async fn udp_proxy_session_task(
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    socks5_addr: SocketAddr,
    mut fwd_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: mpsc::UnboundedSender<UdpMsg>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_tcp_keepalive, relay_addr) = socks5_udp_associate(socks5_addr).await?;

    debug!("UDP proxy: session {src_addr}→{dst_addr} via relay {relay_addr}");

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    let mut recv_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            msg = tokio::time::timeout(UDP_IDLE_TIMEOUT, fwd_rx.recv()) => {
                match msg {
                    Ok(Some(data)) => {
                        let framed = build_socks5_udp_request(dst_addr, &data);
                        if let Err(e) = sock.send_to(&framed, relay_addr).await {
                            warn!("UDP proxy: send to relay failed: {e}");
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
            result = tokio::time::timeout(UDP_IDLE_TIMEOUT, sock.recv_from(&mut recv_buf)) => {
                match result {
                    Ok(Ok((n, _from))) => {
                        let data = &recv_buf[..n];
                        // RSV(2) + FRAG(1) + ATYP...
                        if data.len() < 4 {
                            continue;
                        }
                        match parse_socks5_udp_response(&data[3..]) {
                            Ok((header_len, real_src, ())) => {
                                let payload_start = 3 + header_len;
                                if payload_start <= n {
                                    let payload = data[payload_start..n].to_vec();
                                    let _ = resp_tx.send((payload, real_src, src_addr));
                                }
                            }
                            Err(e) => {
                                debug!("UDP proxy: bad response header: {e}");
                                continue;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("UDP proxy: recv failed: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("UDP proxy: idle timeout");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Perform SOCKS5 UDP ASSOCIATE handshake.
/// Returns (tcp_keepalive_stream, relay_udp_addr).
async fn socks5_udp_associate(
    socks5_addr: SocketAddr,
) -> Result<(TcpStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(socks5_addr).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut gr = [0u8; 2];
    stream.read_exact(&mut gr).await?;
    if gr != [0x05, 0x00] {
        return Err("SOCKS5 UDP ASSOCIATE: greeting rejected".into());
    }

    // UDP ASSOCIATE — client bind addr 0.0.0.0:0
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(format!("SOCKS5 UDP ASSOCIATE: bad version {}", hdr[0]).into());
    }
    if hdr[1] != 0x00 {
        return Err(format!("SOCKS5 UDP ASSOCIATE: rejected with code {}", hdr[1]).into());
    }

    let relay_addr = match hdr[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv4Addr::from(addr);
            let port = u16::from_be_bytes(port);
            SocketAddr::from((ip, port))
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let ip = std::net::Ipv6Addr::from(addr);
            let port = u16::from_be_bytes(port);
            SocketAddr::from((ip, port))
        }
        atyp => {
            return Err(format!("SOCKS5 UDP ASSOCIATE: unsupported bind ATYP {atyp}").into());
        }
    };

    Ok((stream, relay_addr))
}

/// Build SOCKS5 §7 UDP request: [RSV(2), FRAG(1), ATYP, ADDR, PORT, DATA]
fn build_socks5_udp_request(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + payload.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG=0
    match dst {
        SocketAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(payload);
    buf
}

/// Parse SOCKS5 §7 UDP response header (starting from ATYP byte at data[0]).
/// Returns (header_length, source_addr, ()).
fn parse_socks5_udp_response(
    data: &[u8],
) -> Result<(usize, SocketAddr, ()), Box<dyn std::error::Error + Send + Sync>> {
    if data.is_empty() {
        return Err("empty UDP response header".into());
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err("IPv4 UDP response too short".into());
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((7, SocketAddr::from((ip, port)), ()))
        }
        0x04 => {
            if data.len() < 19 {
                return Err("IPv6 UDP response too short".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((19, SocketAddr::from((ip, port)), ()))
        }
        atyp => Err(format!("unknown ATYP in UDP response: {atyp}").into()),
    }
}
