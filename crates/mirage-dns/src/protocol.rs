use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} type={} class={}", self.qname, self.qtype, self.qclass)
    }
}

pub struct ParsedHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
}

pub fn parse_header(buf: &[u8]) -> Option<ParsedHeader> {
    if buf.len() < 12 {
        return None;
    }
    // The header of a DNS message: id, flags, and then four counts:
    // the questions, the answers, the authorities and the additionals.
    Some(ParsedHeader {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        flags: u16::from_be_bytes([buf[2], buf[3]]),
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
    })
}

pub fn parse_question(buf: &[u8]) -> Option<(DnsQuestion, usize)> {
    let header = parse_header(buf)?;
    if header.qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let qname = read_name(buf, &mut pos)?;
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    pos += 4;
    let qname_lower = qname.to_ascii_lowercase();
    Some((DnsQuestion { qname: qname_lower, qtype, qclass }, pos))
}

pub fn min_ttl_from_response(buf: &[u8]) -> Option<u32> {
    let header = parse_header(buf)?;
    let mut pos = 12;
    // Skip question section
    for _ in 0..header.qdcount {
        skip_name(buf, &mut pos)?;
        pos += 4; // qtype + qclass
        if pos > buf.len() {
            return None;
        }
    }
    let mut min_ttl: Option<u32> = None;
    let total_rr = header.ancount;
    for _ in 0..total_rr {
        skip_name(buf, &mut pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        // type(2) + class(2) + ttl(4) + rdlength(2)
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if pos > buf.len() {
            return None;
        }
        min_ttl = Some(min_ttl.map_or(ttl, |m: u32| m.min(ttl)));
    }
    min_ttl
}

pub fn is_nxdomain(buf: &[u8]) -> bool {
    parse_header(buf).map_or(false, |h| (h.flags & 0x000F) == 3)
}

/// Parse A (type 1) and AAAA (type 28) answer records from a DNS wire response.
///
/// Returns a vec of resolved `IpAddr`s from all answer RRs.  Silently ignores
/// malformed records and non-A/AAAA types.  Call this on the upstream's
/// response to extract which IPs a queried name resolved to.
pub fn parse_answer_ips(buf: &[u8]) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let header = match parse_header(buf) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let mut pos = 12usize;

    // Skip question section
    for _ in 0..header.qdcount {
        if skip_name(buf, &mut pos).is_none() {
            return Vec::new();
        }
        pos += 4; // qtype + qclass
        if pos > buf.len() {
            return Vec::new();
        }
    }

    let mut ips = Vec::new();
    for _ in 0..header.ancount {
        if skip_name(buf, &mut pos).is_none() {
            break;
        }
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        // skip type(2) + class(2) + ttl(4)
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        match rtype {
            1 if rdlength == 4 => {
                let octets: [u8; 4] = buf[pos..pos + 4].try_into().unwrap_or([0; 4]);
                ips.push(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            28 if rdlength == 16 => {
                let octets: [u8; 16] = buf[pos..pos + 16].try_into().unwrap_or([0; 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    ips
}

fn read_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut p = *pos;
    let mut jumped = false;
    let mut jump_count = 0;
    loop {
        if p >= buf.len() {
            return None;
        }
        let len = buf[p] as usize;
        if len == 0 {
            if !jumped {
                *pos = p + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if p + 1 >= buf.len() {
                return None;
            }
            if !jumped {
                *pos = p + 2;
                jumped = true;
            }
            p = ((len & 0x3F) << 8 | buf[p + 1] as usize) as usize;
            jump_count += 1;
            if jump_count > 64 {
                return None;
            }
            continue;
        }
        p += 1;
        if p + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[p..p + len]).into_owned());
        p += len;
    }
    Some(labels.join("."))
}

fn skip_name(buf: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        if *pos >= buf.len() {
            return None;
        }
        let len = buf[*pos] as usize;
        if len == 0 {
            *pos += 1;
            return Some(());
        }
        if len & 0xC0 == 0xC0 {
            *pos += 2;
            return Some(());
        }
        *pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: id=0x1234, flags=0x0100 (RD), qdcount=1
        buf.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount
        buf.extend_from_slice(&[0x00, 0x00]); // ancount
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // IN class
        buf
    }

    #[test]
    fn parse_simple_query() {
        let buf = build_query("example.com", 1);
        let (q, _) = parse_question(&buf).unwrap();
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, 1);
    }

    #[test]
    fn parse_uppercase_normalized() {
        let buf = build_query("Example.COM", 28);
        let (q, _) = parse_question(&buf).unwrap();
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, 28);
    }

    #[test]
    fn parse_empty_buf() {
        assert!(parse_header(&[]).is_none());
        assert!(parse_question(&[]).is_none());
    }

    #[test]
    fn parse_too_short() {
        // 11 bytes — one byte shy of the 12-byte minimum header
        let buf = [0u8; 11];
        assert!(parse_header(&buf).is_none());
        assert!(parse_question(&buf).is_none());
    }

    /// Build a DNS response with a compressed name pointer in the answer section.
    /// The question section names the owner with uncompressed labels; the answer
    /// section references it back via a 0xC0 0x0C pointer (offset 12).
    fn build_response_with_ptr_compression(name: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: id=0x5678, flags=0x8180 (QR+RD+RA), qdcount=1, ancount=1
        buf.extend_from_slice(&[0x56, 0x78, 0x81, 0x80]); // id + flags
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount  (bytes 4-5)
        buf.extend_from_slice(&[0x00, 0x01]); // ancount (bytes 6-7)
        buf.extend_from_slice(&[0x00, 0x00]); // nscount (bytes 8-9)
        buf.extend_from_slice(&[0x00, 0x00]); // arcount (bytes 10-11)

        // Question: uncompressed name
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

        // Answer: compressed pointer back to offset 12
        buf.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name at offset 12
        buf.extend_from_slice(&1u16.to_be_bytes()); // type A
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&ttl.to_be_bytes());  // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // rdlength = 4
        buf.extend_from_slice(&[1, 2, 3, 4]);       // rdata (dummy IPv4)
        buf
    }

    #[test]
    fn parse_ptr_compression() {
        let buf = build_response_with_ptr_compression("example.com", 300);
        let ttl = min_ttl_from_response(&buf).unwrap();
        assert_eq!(ttl, 300);
    }

    /// Build a minimal DNS response with a given RCODE in the flags.
    fn build_response_rcode(rcode: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        // QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=rcode
        let flags: u16 = 0x8180 | (rcode as u16 & 0x000F);
        buf.extend_from_slice(&[0x00, 0x01]); // id
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // qdcount=0
        buf.extend_from_slice(&[0x00, 0x00]); // ancount=0
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount
        buf
    }

    #[test]
    fn nxdomain_detection() {
        let buf = build_response_rcode(3);
        assert!(is_nxdomain(&buf));
    }

    #[test]
    fn non_nxdomain() {
        let buf = build_response_rcode(0);
        assert!(!is_nxdomain(&buf));
    }

    /// The answer count is read from the place the wire keeps it.
    ///
    /// The header of a DNS message is: id, flags, and then the counts of the
    /// questions, the answers, the authorities and the additionals.  The
    /// answers live in bytes 6 and 7; reading them from bytes 8 and 9 (the
    /// authorities) made every answer look like there was none -- and the
    /// bypass, which follows the names, never learned an address.
    #[test]
    fn the_answer_count_is_read_from_the_wire() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]); // id + flags
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount
        buf.extend_from_slice(&[0x00, 0x02]); // ancount = 2
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount
        // the question: example.com A IN
        for label in ["example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        // two answers, each a compressed pointer back to the question
        for ip in [[1u8, 2, 3, 4], [5, 6, 7, 8]] {
            buf.extend_from_slice(&[0xC0, 0x0C]);
            buf.extend_from_slice(&1u16.to_be_bytes()); // type A
            buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
            buf.extend_from_slice(&300u32.to_be_bytes()); // TTL
            buf.extend_from_slice(&4u16.to_be_bytes()); // rdlength
            buf.extend_from_slice(&ip);
        }

        let header = parse_header(&buf).expect("the header parses");
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 2);

        let ips = parse_answer_ips(&buf);
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<std::net::IpAddr>().unwrap(),
                "5.6.7.8".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
        assert_eq!(min_ttl_from_response(&buf), Some(300));
    }
}
