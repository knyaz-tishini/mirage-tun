use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::protocol::DnsQuestion;

struct CacheEntry {
    response: Vec<u8>,
    inserted: Instant,
    ttl: Duration,
}

pub struct DnsCache {
    inner: LruCache<DnsQuestion, CacheEntry>,
    neg_ttl: Duration,
}

pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: LruCache::new(cap),
            neg_ttl: Duration::from_secs(60),
        }
    }

    /// Look up a cached response. Returns None if expired or missing.
    /// Rewrites the DNS header ID to match the query.
    pub fn get(&mut self, question: &DnsQuestion, query_id: u16) -> Option<Vec<u8>> {
        let entry = self.inner.get(question)?;
        if entry.inserted.elapsed() >= entry.ttl {
            self.inner.pop(question);
            return None;
        }
        let mut resp = entry.response.clone();
        // Rewrite transaction ID to match current query
        if resp.len() >= 2 {
            let id_bytes = query_id.to_be_bytes();
            resp[0] = id_bytes[0];
            resp[1] = id_bytes[1];
        }
        Some(resp)
    }

    /// Store a response in cache with given TTL.
    pub fn put(&mut self, question: DnsQuestion, response: Vec<u8>, ttl: Duration) {
        let ttl = if ttl.is_zero() { self.neg_ttl } else { ttl };
        self.inner.put(question, CacheEntry {
            response,
            inserted: Instant::now(),
            ttl,
        });
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.inner.len(),
            capacity: self.inner.cap().get(),
            hits: 0,
            misses: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str) -> DnsQuestion {
        DnsQuestion {
            qname: name.to_string(),
            qtype: 1,
            qclass: 1,
        }
    }

    #[test]
    fn cache_hit_rewrites_id() {
        let mut cache = DnsCache::new(10);
        let q = question("example.com");
        let resp = vec![0xAA, 0xBB, 0x81, 0x80]; // id=0xAABB
        cache.put(q.clone(), resp, Duration::from_secs(300));

        let result = cache.get(&q, 0x1234).unwrap();
        assert_eq!(result[0], 0x12);
        assert_eq!(result[1], 0x34);
    }

    #[test]
    fn cache_miss_after_expiry() {
        let mut cache = DnsCache::new(10);
        let q = question("expired.com");
        cache.put(q.clone(), vec![0, 0], Duration::from_millis(1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(cache.get(&q, 0).is_none());
    }
}
