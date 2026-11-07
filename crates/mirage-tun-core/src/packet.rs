//! Minimal read-only IP packet parser.
//!
//! Extracts the 5-tuple (protocol, src_ip, src_port, dst_ip, dst_port) from
//! raw Layer-3 packets.  Used by the userspace NAT path and by the UDP DNS
//! take-over path.
//!
//! No options parsing.  No reassembly.  No packet construction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Wire protocol number carried inside the IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    /// Any other IP protocol number.
    Other(u8),
}

impl Protocol {
    fn from_u8(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            n => Self::Other(n),
        }
    }
}

/// Decoded 5-tuple extracted from one IP packet.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    /// Source port, or `None` for protocols that carry no port.
    pub src_port: Option<u16>,
    /// Destination port, or `None` for protocols that carry no port.
    pub dst_port: Option<u16>,
    /// Total packet length in bytes (from the IP header).
    pub total_len: usize,
}

/// Error returned when the packet buffer is malformed or too short.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("packet too short: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("unknown IP version: {0}")]
    UnknownVersion(u8),
}

/// Parse `buf` as a raw IP packet and return the decoded 5-tuple.
///
/// Returns [`ParseError::TooShort`] when the buffer is smaller than the
/// minimum required header size.  Fragmented packets are parsed as-is — port
/// fields may read garbage for non-first fragments, which is acceptable for
/// our NAT lookup use-case.
pub fn parse(buf: &[u8]) -> Result<PacketInfo, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::TooShort { need: 1, got: 0 });
    }

    let version = buf[0] >> 4;
    match version {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        v => Err(ParseError::UnknownVersion(v)),
    }
}

// ── IPv4 ──────────────────────────────────────────────────────────────────────

fn parse_ipv4(buf: &[u8]) -> Result<PacketInfo, ParseError> {
    // Minimum IPv4 header is 20 bytes.
    if buf.len() < 20 {
        return Err(ParseError::TooShort { need: 20, got: buf.len() });
    }

    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if buf.len() < ihl {
        return Err(ParseError::TooShort { need: ihl, got: buf.len() });
    }

    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let protocol = Protocol::from_u8(buf[9]);
    let src_ip = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let (src_port, dst_port) = parse_ports(protocol, &buf[ihl..]);

    Ok(PacketInfo { protocol, src_ip, dst_ip, src_port, dst_port, total_len })
}

// ── IPv6 ──────────────────────────────────────────────────────────────────────

fn parse_ipv6(buf: &[u8]) -> Result<PacketInfo, ParseError> {
    // Fixed IPv6 header is 40 bytes.
    const IPV6_HDR: usize = 40;
    if buf.len() < IPV6_HDR {
        return Err(ParseError::TooShort { need: IPV6_HDR, got: buf.len() });
    }

    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total_len = IPV6_HDR + payload_len;
    let next_header = buf[6];
    let protocol = Protocol::from_u8(next_header);

    let src_ip = IpAddr::V6(Ipv6Addr::from(read16(&buf[8..24])));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(read16(&buf[24..40])));

    let (src_port, dst_port) = parse_ports(protocol, &buf[IPV6_HDR..]);

    Ok(PacketInfo { protocol, src_ip, dst_ip, src_port, dst_port, total_len })
}

// ── Transport headers ─────────────────────────────────────────────────────────

/// Parse the first four bytes of the transport layer to extract src/dst ports.
///
/// Both TCP and UDP share the same port layout in the first 4 bytes.
fn parse_ports(protocol: Protocol, transport: &[u8]) -> (Option<u16>, Option<u16>) {
    match protocol {
        Protocol::Tcp | Protocol::Udp => {
            if transport.len() < 4 {
                return (None, None);
            }
            let src = u16::from_be_bytes([transport[0], transport[1]]);
            let dst = u16::from_be_bytes([transport[2], transport[3]]);
            (Some(src), Some(dst))
        }
        Protocol::Other(_) => (None, None),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read16(slice: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&slice[..16]);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal hand-crafted IPv4/UDP packet:
    /// 10.0.85.2:12345 → 8.8.8.8:53
    #[rustfmt::skip]
    const UDP_PKT: &[u8] = &[
        // IPv4 header (20 bytes)
        0x45, 0x00, 0x00, 0x1c, // version/IHL, DSCP, total length = 28
        0x00, 0x01, 0x00, 0x00, // id, flags/frag offset
        0x40, 0x11,             // TTL=64, protocol=17 (UDP)
        0x00, 0x00,             // checksum (0 for test)
        0x0a, 0x00, 0x55, 0x02, // src = 10.0.85.2
        0x08, 0x08, 0x08, 0x08, // dst = 8.8.8.8
        // UDP header (8 bytes)
        0x30, 0x39,             // src port = 12345
        0x00, 0x35,             // dst port = 53
        0x00, 0x08,             // length = 8
        0x00, 0x00,             // checksum (0 for test)
    ];

    #[test]
    fn parse_ipv4_udp() {
        let info = parse(UDP_PKT).expect("parse failed");
        assert_eq!(info.protocol, Protocol::Udp);
        assert_eq!(info.src_ip, "10.0.85.2".parse::<IpAddr>().unwrap());
        assert_eq!(info.dst_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(info.src_port, Some(12345));
        assert_eq!(info.dst_port, Some(53));
        assert_eq!(info.total_len, 28);
    }

    #[test]
    fn parse_too_short() {
        assert!(matches!(parse(&[0x45]), Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn parse_empty() {
        assert!(matches!(parse(&[]), Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn parse_unknown_version() {
        let buf = [0x30u8; 20]; // version 3
        assert!(matches!(parse(&buf), Err(ParseError::UnknownVersion(3))));
    }
}
