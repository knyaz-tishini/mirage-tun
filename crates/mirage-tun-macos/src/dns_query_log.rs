/// Forward-DNS query log: IP → (forward query name, insertion timestamp).
///
/// Populated by the DNS-intercept loop whenever a DNS A/AAAA answer arrives
/// through the TUN.  Queried at TCP/UDP flow-creation time to attach the
/// originating forward query name to the connection snapshot.
///
/// Bounds:
/// - Hard cap of `MAX_ENTRIES` entries.  When the cap is reached the oldest
///   entry (by insertion order) is evicted before inserting the new one.
/// - Each entry expires after `TTL_SECS` seconds; expired entries are evicted
///   lazily on every `insert` call and eagerly on `lookup`.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Maximum number of IP→name entries retained simultaneously.
const MAX_ENTRIES: usize = 4096;
/// How long (seconds) an entry remains valid after insertion.
const TTL_SECS: u64 = 300;

struct Entry {
    name: String,
    inserted_at: Instant,
}

struct Inner {
    map: HashMap<IpAddr, Entry>,
    /// Insertion-order queue for LRU-style eviction when at capacity.
    order: VecDeque<IpAddr>,
}

/// Shared, thread-safe forward-DNS query log.
pub struct DnsQueryLog {
    inner: Mutex<Inner>,
}

impl DnsQueryLog {
    pub fn new() -> Self {
        DnsQueryLog {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Insert every resolved IP from a successful DNS answer, associating it
    /// with `forward_name` (the qname from the original query, already
    /// lower-cased by `protocol::parse_question`).
    pub fn insert_ips(&self, forward_name: &str, ips: &[IpAddr]) {
        if ips.is_empty() {
            return;
        }
        let mut g = self
            .inner
            .lock()
            .expect("DnsQueryLog lock poisoned");
        let now = Instant::now();

        // Evict expired entries first (lazy sweep).
        // Collect expired IPs first, then remove — avoids double-borrow on `g`.
        let expired: Vec<IpAddr> = g
            .order
            .iter()
            .filter(|ip| {
                g.map
                    .get(*ip)
                    .map(|e| now.duration_since(e.inserted_at).as_secs() >= TTL_SECS)
                    .unwrap_or(true)
            })
            .copied()
            .collect();
        for ip in &expired {
            g.map.remove(ip);
        }
        g.order.retain(|ip| !expired.contains(ip));

        for &ip in ips {
            // If the IP is already known, update in place (no deque churn needed
            // for the common refresh case — just bump the timestamp and name).
            if let Some(e) = g.map.get_mut(&ip) {
                e.name = forward_name.to_owned();
                e.inserted_at = now;
                continue;
            }

            // Evict oldest when at capacity.
            while g.map.len() >= MAX_ENTRIES {
                if let Some(oldest) = g.order.pop_front() {
                    g.map.remove(&oldest);
                }
            }

            g.order.push_back(ip);
            g.map.insert(
                ip,
                Entry {
                    name: forward_name.to_owned(),
                    inserted_at: now,
                },
            );
        }
    }

    /// Look up the forward query name for `ip`.
    ///
    /// Returns `None` if the entry is absent or has expired.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let mut g = self
            .inner
            .lock()
            .expect("DnsQueryLog lock poisoned");
        let entry = g.map.get(&ip)?;
        if Instant::now().duration_since(entry.inserted_at).as_secs() >= TTL_SECS {
            // Expired — evict eagerly.
            g.map.remove(&ip);
            return None;
        }
        Some(entry.name.clone())
    }
}

impl Default for DnsQueryLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, a))
    }

    #[test]
    fn insert_and_lookup() {
        let log = DnsQueryLog::new();
        log.insert_ips("example.com", &[ip(1), ip(2)]);
        assert_eq!(log.lookup(ip(1)).as_deref(), Some("example.com"));
        assert_eq!(log.lookup(ip(2)).as_deref(), Some("example.com"));
        assert!(log.lookup(ip(3)).is_none());
    }

    #[test]
    fn update_existing() {
        let log = DnsQueryLog::new();
        log.insert_ips("old.com", &[ip(1)]);
        log.insert_ips("new.com", &[ip(1)]);
        assert_eq!(log.lookup(ip(1)).as_deref(), Some("new.com"));
    }

    #[test]
    fn capacity_cap() {
        let log = DnsQueryLog::new();
        // Insert MAX_ENTRIES + 1 distinct IPs to verify eviction doesn't panic.
        let ips: Vec<IpAddr> = (0u32..=(MAX_ENTRIES as u32))
            .map(|i| IpAddr::V4(Ipv4Addr::from(i + 0x0A000000)))
            .collect();
        for ip in &ips {
            log.insert_ips("cap-test.example", &[*ip]);
        }
        let g = log.inner.lock().unwrap();
        assert!(g.map.len() <= MAX_ENTRIES);
    }

    #[test]
    fn empty_ips_noop() {
        let log = DnsQueryLog::new();
        log.insert_ips("noop.com", &[]);
        let g = log.inner.lock().unwrap();
        assert!(g.map.is_empty());
    }
}
