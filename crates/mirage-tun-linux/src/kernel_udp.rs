use std::net::SocketAddr;
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use tracing::{debug, warn};

use mirage_tun_core::error::TunError;
use mirage_tun_core::traits::UdpSocket;

// Minimum IP header size (IPv4 without options).
const IPV4_HEADER_MIN: usize = 20;
// UDP header size.
const UDP_HEADER_SIZE: usize = 8;

/// UDP socket that reads raw IP packets from the TUN file descriptor,
/// parses out UDP datagrams, and injects reply packets back.
///
/// On Linux the kernel stack handles TCP itself; UDP still travels through
/// the TUN fd as raw IP packets, so we parse them here. This is the lower
/// half only — `crate::udp_socks5` is the upper half that drives `recv()`
/// in a loop and relays each flow through SOCKS5 UDP ASSOCIATE or direct
/// (`Bypass`), writing replies back through the `WriteSender` returned
/// alongside this socket.
pub struct LinuxKernelUdpSocket {
    /// Sending half: write raw IP/UDP packets back into the TUN fd.
    tun_write_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Receiving half: parsed (payload, src, dst) tuples.
    datagram_rx: tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr, SocketAddr)>,
}

impl LinuxKernelUdpSocket {
    /// Spawn the packet reader loop.
    ///
    /// `tun_fd` must be a non-blocking raw TUN fd (IFF_TUN | IFF_NO_PI).
    /// Returns the `LinuxKernelUdpSocket` and the write sender.
    #[cfg(target_os = "linux")]
    pub fn from_fd(tun_fd: std::os::unix::io::RawFd) -> std::io::Result<(Self, WriteSender)> {
        use tokio::io::unix::AsyncFd;

        let async_fd = AsyncFd::new(unsafe {
            // Duplicate the fd so the AsyncFd owns its own copy.
            let duped = libc::dup(tun_fd);
            if duped < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Make it non-blocking.
            let flags = libc::fcntl(duped, libc::F_GETFL);
            libc::fcntl(duped, libc::F_SETFL, flags | libc::O_NONBLOCK);
            std::fs::File::from_raw_fd(duped)
        })?;

        let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(256);
        let (write_tx, write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let write_sender = WriteSender(write_tx.clone());

        // Reader task: parse raw IP packets → forward UDP datagrams.
        {
            let datagram_tx = datagram_tx.clone();
            tokio::spawn(reader_loop(async_fd, datagram_tx, write_rx));
        }

        Ok((
            Self {
                tun_write_tx: write_tx,
                datagram_rx,
            },
            write_sender,
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_fd(_tun_fd: i32) -> std::io::Result<(Self, WriteSender)> {
        let (_tx, datagram_rx) = tokio::sync::mpsc::channel(1);
        let (write_tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let write_sender = WriteSender(write_tx.clone());
        Ok((
            Self {
                tun_write_tx: write_tx,
                datagram_rx,
            },
            write_sender,
        ))
    }
}

/// Cloneable handle for injecting packets into the TUN write path.
///
/// Handed out alongside `LinuxKernelUdpSocket` so callers that need to write
/// replies from many concurrent tasks (e.g. `udp_socks5`'s per-flow SOCKS5
/// sessions) don't have to fight the socket's own `&mut self` — `recv()` and
/// `send()` both take `&mut self`, so a single owner drives `recv()` in a
/// loop while every other task writes back through a cloned `WriteSender`.
#[derive(Clone)]
pub struct WriteSender(pub tokio::sync::mpsc::Sender<Vec<u8>>);

impl WriteSender {
    /// Build a reply IPv4/UDP packet from `payload` + `(src, dst)` and inject
    /// it into the TUN write path — same packet-building path `send()` on
    /// `LinuxKernelUdpSocket` uses, exposed here so cloned handles can reach
    /// it without a mutable borrow of the socket itself.
    pub async fn send_udp(
        &self,
        payload: &[u8],
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        let pkt = build_udp_ipv4_packet(payload, src, dst);
        self.0
            .send(pkt)
            .await
            .map_err(|_| TunError::Other("TUN write channel closed".into()))
    }
}

#[async_trait]
impl UdpSocket for LinuxKernelUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.datagram_rx.recv().await
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        let pkt = build_udp_ipv4_packet(&payload, src, dst);
        self.tun_write_tx
            .send(pkt)
            .await
            .map_err(|_| TunError::Other("TUN write channel closed".into()))
    }
}

// ── Packet I/O loop ───────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn reader_loop(
    async_fd: tokio::io::unix::AsyncFd<std::fs::File>,
    datagram_tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    mut write_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    use std::io::{Read, Write};

    let mut buf = vec![0u8; 1504];

    loop {
        tokio::select! {
            // Read raw IP packet from TUN.
            guard = async_fd.readable() => {
                match guard {
                    Ok(mut g) => {
                        match g.try_io(|inner| inner.get_ref().read(&mut buf)) {
                            Ok(Ok(n)) if n >= IPV4_HEADER_MIN => {
                                if let Some((payload, src, dst)) = parse_udp_from_ipv4(&buf[..n]) {
                                    debug!("UDP: {src} → {dst}, {n} bytes");
                                    let _ = datagram_tx.send((payload, src, dst)).await;
                                }
                            }
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Ok(Err(e)) => warn!("TUN read error: {e}"),
                            Err(_) => {}
                        }
                    }
                    Err(e) => {
                        warn!("async_fd readable error: {e}");
                        break;
                    }
                }
            }
            // Write injected packet back to TUN.
            pkt = write_rx.recv() => {
                match pkt {
                    Some(p) => {
                        match async_fd.writable().await {
                            Ok(mut g) => {
                                let _ = g.try_io(|inner| inner.get_ref().write_all(&p));
                            }
                            Err(e) => warn!("TUN writable error: {e}"),
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

// ── Packet parsing & building ─────────────────────────────────────────────────

/// Parse a UDP datagram from a raw IPv4 packet. Returns (payload, src, dst).
#[cfg(target_os = "linux")]
fn parse_udp_from_ipv4(pkt: &[u8]) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
    if pkt.len() < IPV4_HEADER_MIN {
        return None;
    }
    // Protocol field at byte 9 (0 = ICMP, 6 = TCP, 17 = UDP).
    let proto = pkt[9];
    if proto != 17 {
        return None;
    }
    // IHL (header length in 32-bit words) in lower nibble of byte 0.
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + UDP_HEADER_SIZE {
        return None;
    }

    let src_ip = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    let udp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;

    if length < UDP_HEADER_SIZE || udp.len() < length {
        return None;
    }

    let payload = udp[UDP_HEADER_SIZE..length].to_vec();
    let src = SocketAddr::from((src_ip, src_port));
    let dst = SocketAddr::from((dst_ip, dst_port));

    Some((payload, src, dst))
}

/// Build a minimal IPv4/UDP packet from payload + (src, dst) addresses.
fn build_udp_ipv4_packet(payload: &[u8], src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (src_ip, src_port, dst_ip, dst_port) = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            (s.ip().octets(), s.port(), d.ip().octets(), d.port())
        }
        _ => {
            // IPv6 UDP-in-TUN not handled here — return empty.
            return Vec::new();
        }
    };

    let udp_len = (UDP_HEADER_SIZE + payload.len()) as u16;
    let total_len = (IPV4_HEADER_MIN as u16) + udp_len;

    let mut pkt = vec![0u8; total_len as usize];

    // IPv4 header
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xff) as u8;
    pkt[4] = 0x00; // identification (hi)
    pkt[5] = 0x01; // identification (lo)
    pkt[6] = 0x40; // flags: DF
    pkt[7] = 0x00; // fragment offset
    pkt[8] = 64;   // TTL
    pkt[9] = 17;   // protocol: UDP
    pkt[10] = 0x00; // checksum (hi) — computed below
    pkt[11] = 0x00; // checksum (lo)
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);

    // IP header checksum
    let checksum = ipv4_checksum(&pkt[..IPV4_HEADER_MIN]);
    pkt[10] = (checksum >> 8) as u8;
    pkt[11] = (checksum & 0xff) as u8;

    // UDP header
    let udp_start = IPV4_HEADER_MIN;
    pkt[udp_start] = (src_port >> 8) as u8;
    pkt[udp_start + 1] = (src_port & 0xff) as u8;
    pkt[udp_start + 2] = (dst_port >> 8) as u8;
    pkt[udp_start + 3] = (dst_port & 0xff) as u8;
    pkt[udp_start + 4] = (udp_len >> 8) as u8;
    pkt[udp_start + 5] = (udp_len & 0xff) as u8;
    pkt[udp_start + 6] = 0x00; // checksum hi (optional, set to 0)
    pkt[udp_start + 7] = 0x00; // checksum lo

    // Payload
    pkt[udp_start + UDP_HEADER_SIZE..].copy_from_slice(payload);

    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[cfg(target_os = "linux")]
    #[test]
    fn round_trip_udp_packet() {
        use std::str::FromStr;
        let payload = b"hello udp";
        let src: SocketAddr = SocketAddr::from_str("10.0.0.1:12345").unwrap();
        let dst: SocketAddr = SocketAddr::from_str("8.8.8.8:53").unwrap();

        let pkt = build_udp_ipv4_packet(payload, src, dst);
        assert!(pkt.len() >= IPV4_HEADER_MIN + UDP_HEADER_SIZE + payload.len());

        let parsed = parse_udp_from_ipv4(&pkt).unwrap();
        assert_eq!(parsed.0, payload);
        assert_eq!(parsed.1, src);
        assert_eq!(parsed.2, dst);
    }

    #[test]
    fn ipv4_checksum_zero_on_valid_header() {
        // Build packet and verify header checksum validates.
        let payload = b"test";
        let src: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let pkt = build_udp_ipv4_packet(payload, src, dst);
        // Checksum of header including embedded checksum should be 0xFFFF or 0.
        let check = ipv4_checksum(&pkt[..IPV4_HEADER_MIN]);
        assert_eq!(check, 0);
    }
}
