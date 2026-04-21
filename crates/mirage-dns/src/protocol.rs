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
    Some(ParsedHeader {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        flags: u16::from_be_bytes([buf[2], buf[3]]),
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[8], buf[9]]),
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
}
