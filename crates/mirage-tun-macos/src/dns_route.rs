/// DNS-via-SOCKS5 for macOS TUN stack.
///
/// Mirrors Windows `dns_via_socks5_inner` in mirage-tun-windows/src/ipstack.rs.
/// On macOS there is no per-interface binding, so `if_index` is absent.
///
/// Semantics: intercept UDP :53 in the smoltcp read loop, forward the raw
/// DNS wire payload over a SOCKS5 TCP CONNECT to `dns_upstream` (the
/// per-chain or global DNS resolver), return the raw wire response.
/// This prevents DNS from leaking out the utun directly and ensures
/// resolution follows the chain's SOCKS5 path.
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Forward one DNS UDP query through `socks5_addr` to `dns_upstream`.
/// Retries once on transient errors (mirrors Windows behaviour).
pub(crate) async fn dns_via_socks5(
    query: &[u8],
    socks5_addr: SocketAddr,
    dns_upstream: SocketAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for attempt in 0..2u8 {
        match dns_tcp_query(query, socks5_addr, dns_upstream).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = Some(e);
                if attempt == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

async fn dns_tcp_query(
    query: &[u8],
    socks5_addr: SocketAddr,
    dns_upstream: SocketAddr,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = socks5_connect(socks5_addr, dns_upstream).await?;

    // DNS-over-TCP: 2-byte big-endian length prefix.
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 65535 {
        return Err("DNS response too large".into());
    }

    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// SOCKS5 no-auth CONNECT (RFC 1928).
async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(proxy).await?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut gr = [0u8; 2];
    stream.read_exact(&mut gr).await?;
    if gr[0] != 0x05 || gr[1] != 0x00 {
        return Err(format!("SOCKS5 greeting rejected: {:02x} {:02x}", gr[0], gr[1]).into());
    }

    // CONNECT request.
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(format!("SOCKS5 CONNECT: bad VER {}", hdr[0]).into());
    }
    if hdr[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected, code 0x{:02x}", hdr[1]).into());
    }

    // Drain bound address from response.
    let skip = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        atyp => {
            return Err(format!("SOCKS5 CONNECT: unknown ATYP 0x{:02x}", atyp).into());
        }
    };
    let mut tail = vec![0u8; skip];
    stream.read_exact(&mut tail).await?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid DNS query for "example.com A" (wire format, no TC prefix).
    fn make_example_com_query() -> Vec<u8> {
        // Transaction ID: 0xAB CD
        // Flags: 0x01 00 (standard query, recursion desired)
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        // QNAME: 7 "example" 3 "com" 0
        // QTYPE=A(1), QCLASS=IN(1)
        vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,          // root label
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ]
    }

    #[test]
    fn query_len_fits_u16() {
        let q = make_example_com_query();
        // Must be encodable as u16 length prefix for DNS-over-TCP.
        assert!(q.len() <= u16::MAX as usize);
        let _len_bytes = (q.len() as u16).to_be_bytes();
    }

    #[test]
    fn socks5_connect_request_ipv4() {
        // Validate the CONNECT request bytes for an IPv4 target.
        let target: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let mut req = Vec::with_capacity(10);
        req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER CMD RSV
        match target {
            SocketAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.ip().octets());
                req.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(_) => unreachable!(),
        }
        // VER=5 CMD=CONNECT RSV=0 ATYP=IPv4 IP[4] PORT[2]
        assert_eq!(req.len(), 10);
        assert_eq!(req[0], 0x05);
        assert_eq!(req[1], 0x01); // CONNECT
        assert_eq!(req[3], 0x01); // IPv4
        // 1.1.1.1
        assert_eq!(&req[4..8], &[1, 1, 1, 1]);
        // port 53 = 0x00 0x35
        assert_eq!(&req[8..10], &[0x00, 0x35]);
    }

    #[test]
    fn socks5_connect_request_ipv6() {
        let target: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let mut req = Vec::with_capacity(22);
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        match target {
            SocketAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.ip().octets());
                req.extend_from_slice(&v6.port().to_be_bytes());
            }
            SocketAddr::V4(_) => unreachable!(),
        }
        assert_eq!(req.len(), 22);
        assert_eq!(req[3], 0x04); // IPv6
    }
}
