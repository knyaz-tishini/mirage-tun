/// macOS kernel UDP socket — parses raw UDP packets from the TUN fd.
///
/// On macOS the kernel handles IP/TCP/UDP normally once packets are injected
/// via the utun fd. For UDP we parse packets directly from the TUN read loop
/// rather than setting up a redirect (pf UDP redirect is harder to use for
/// transparent proxy purposes).
///
/// The `MacosKernelUdpSocket` owns a channel:
///   - The TUN read task sends raw IP packets into `tx`.
///   - `recv()` reads from `rx`, parses the UDP datagram, returns payload + addrs.
///   - `send()` injects a crafted UDP reply packet back through the TUN fd.
use async_trait::async_trait;
use mirage_tun_core::error::TunError;
use mirage_tun_core::traits::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Channel depth for the UDP packet queue.
const UDP_CHANNEL_DEPTH: usize = 512;

/// A parsed UDP datagram from the TUN fd.
#[derive(Debug)]
pub struct RawUdpPacket {
    pub payload: Vec<u8>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// Receives raw IP packets from the TUN read loop and feeds them into the channel.
pub type UdpPacketSender = mpsc::Sender<Vec<u8>>;

/// macOS UDP socket backed by parsing raw IP packets from the TUN fd.
pub struct MacosKernelUdpSocket {
    rx: mpsc::Receiver<Vec<u8>>,
    /// Sender used to inject reply packets back into the TUN fd.
    /// Arc so it can be cloned into the stack runner.
    packet_tx: Arc<mpsc::Sender<Vec<u8>>>,
}

impl MacosKernelUdpSocket {
    /// Create a new socket pair.
    ///
    /// Returns `(socket, raw_pkt_sender, reply_rx)`:
    /// - `raw_pkt_sender`: call `.send(ip_packet)` from the TUN read loop.
    /// - `reply_rx`: receive crafted reply IP packets to write back to the TUN fd.
    pub fn new() -> (
        MacosKernelUdpSocket,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<u8>>(UDP_CHANNEL_DEPTH);
        let (reply_tx, reply_rx) = mpsc::channel::<Vec<u8>>(UDP_CHANNEL_DEPTH);
        let socket = MacosKernelUdpSocket {
            rx: raw_rx,
            packet_tx: Arc::new(reply_tx),
        };
        (socket, raw_tx, reply_rx)
    }
}

#[async_trait]
impl UdpSocket for MacosKernelUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        loop {
            let raw = self.rx.recv().await?;
            match parse_udp_packet(&raw) {
                Some(pkt) => return Some((pkt.payload, pkt.src, pkt.dst)),
                None => {
                    // Not a UDP packet or malformed — skip
                    debug!("skipped non-UDP or malformed packet ({} bytes)", raw.len());
                }
            }
        }
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        let packet = craft_udp_packet(&payload, src, dst)
            .ok_or_else(|| TunError::Other("UDP packet craft failed".to_string()))?;

        self.packet_tx
            .send(packet)
            .await
            .map_err(|_| TunError::Other("UDP reply channel closed".to_string()))
    }
}

// ── Packet parsing ─────────────────────────────────────────────────────────────

/// Parse a raw IPv4 packet and extract UDP payload + source/destination addresses.
/// Returns `None` if the packet is not UDP or is malformed.
fn parse_udp_packet(raw: &[u8]) -> Option<RawUdpPacket> {
    if raw.len() < 20 {
        return None;
    }

    let version = raw[0] >> 4;
    if version != 4 {
        // IPv6 UDP not implemented in this version
        return None;
    }

    let ihl = (raw[0] & 0x0F) as usize * 4;
    if raw.len() < ihl + 8 {
        return None;
    }

    let protocol = raw[9];
    if protocol != 17 {
        // Not UDP (17)
        return None;
    }

    let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
    let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

    let udp = &raw[ihl..];
    if udp.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;

    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }

    let payload = udp[8..udp_len].to_vec();

    Some(RawUdpPacket {
        payload,
        src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dst: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
    })
}

/// Craft a minimal IPv4/UDP packet for the given payload and addresses.
/// `src` and `dst` are the addresses as seen by the network (i.e. reply direction).
fn craft_udp_packet(payload: &[u8], src: SocketAddr, dst: SocketAddr) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => (s.ip().octets(), d.ip().octets()),
        _ => {
            warn!("IPv6 UDP craft not supported");
            return None;
        }
    };

    let udp_len = (8 + payload.len()) as u16;
    let total_len = (20 + udp_len) as u16;

    let mut pkt = vec![0u8; 20 + udp_len as usize];

    // IPv4 header
    pkt[0] = 0x45; // version=4, ihl=5
    pkt[1] = 0; // DSCP/ECN
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xFF) as u8;
    pkt[4] = 0; // id high
    pkt[5] = 0; // id low
    pkt[6] = 0x40; // flags: DF
    pkt[7] = 0; // fragment offset
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol: UDP
    // checksum at [10..12] — compute below
    pkt[12..16].copy_from_slice(&src_ip);
    pkt[16..20].copy_from_slice(&dst_ip);

    let ip_csum = ip_checksum(&pkt[..20]);
    pkt[10] = (ip_csum >> 8) as u8;
    pkt[11] = (ip_csum & 0xFF) as u8;

    // UDP header
    let src_port = src.port();
    let dst_port = dst.port();
    pkt[20] = (src_port >> 8) as u8;
    pkt[21] = (src_port & 0xFF) as u8;
    pkt[22] = (dst_port >> 8) as u8;
    pkt[23] = (dst_port & 0xFF) as u8;
    pkt[24] = (udp_len >> 8) as u8;
    pkt[25] = (udp_len & 0xFF) as u8;
    // UDP checksum at [26..28] — optional for IPv4, leave as 0
    pkt[26] = 0;
    pkt[27] = 0;
    pkt[28..].copy_from_slice(payload);

    Some(pkt)
}

/// Compute RFC 1071 one's complement checksum over a byte slice.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_value() {
        // IP header with zero checksum field — sum should be non-zero
        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, // checksum = 0
            0xac, 0x10, 0x0a, 0x63, // src 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // dst 172.16.10.12
        ];
        let csum = ip_checksum(&header);
        assert_ne!(csum, 0);
    }

    #[test]
    fn parse_and_craft_roundtrip() {
        let payload = b"hello";
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:53".parse().unwrap();

        let pkt = craft_udp_packet(payload, src, dst).unwrap();
        let parsed = parse_udp_packet(&pkt).unwrap();

        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
    }

    #[test]
    fn parse_non_udp_returns_none() {
        // Build a TCP packet (protocol = 6)
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        assert!(parse_udp_packet(&pkt).is_none());
    }
}
