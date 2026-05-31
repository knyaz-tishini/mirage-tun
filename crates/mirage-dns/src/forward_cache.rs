use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, broadcast};

use crate::cache::DnsCache;
use crate::protocol::{self, DnsQuestion};

/// Combined DNS cache + singleflight deduplication layer.
///
/// `resolve` is the only entry point. Concurrent queries for the same
/// `(qname, qtype, qclass)` tuple will wait on the first (leader) query
/// and share its result, avoiding N parallel SOCKS5 TCP CONNECTs.
/// Responses are cached by TTL from the wire response.
pub struct ForwardCache {
    cache: Mutex<DnsCache>,
    in_flight: Mutex<HashMap<DnsQuestion, broadcast::Sender<Arc<Vec<u8>>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardError<E: std::fmt::Display> {
    #[error("query too short")]
    TooShort,
    #[error("malformed query")]
    Malformed,
    #[error("singleflight leader failed")]
    LeaderFailed,
    #[error("forward failed: {0}")]
    Forward(E),
}

impl ForwardCache {
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache: Mutex::new(DnsCache::new(cache_size)),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// Cache + singleflight around `forward`. `forward` is invoked at most once
    /// per unique `(qname, qtype, qclass)` in flight; concurrent identical
    /// queries wait on the leader's result; cached results (TTL from response)
    /// short-circuit the forward entirely.
    pub async fn resolve<F, Fut, E>(
        &self,
        query: &[u8],
        forward: F,
    ) -> Result<Vec<u8>, ForwardError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, E>>,
        E: std::fmt::Display,
    {
        // Step 1: basic parse.
        if query.len() < 12 {
            return Err(ForwardError::TooShort);
        }
        let header = protocol::parse_header(query).ok_or(ForwardError::Malformed)?;
        let qid = header.id;
        let (question, _) = protocol::parse_question(query).ok_or(ForwardError::Malformed)?;

        // Step 2: cache lookup.
        {
            let mut cache = self.cache.lock().await;
            if let Some(resp) = cache.get(&question, qid) {
                return Ok(resp);
            }
        }

        // Step 3: singleflight — are we leader or follower?
        let maybe_rx = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(tx) = in_flight.get(&question) {
                // Follower: subscribe before dropping the lock.
                Some(tx.subscribe())
            } else {
                // Leader: insert a fresh sender.
                let (tx, _) = broadcast::channel(4);
                in_flight.insert(question.clone(), tx);
                None
            }
        };

        if let Some(mut rx) = maybe_rx {
            // Step 4: FOLLOWER path.
            match rx.recv().await {
                Ok(arc_raw) => {
                    let mut resp = (*arc_raw).clone();
                    if resp.len() >= 2 {
                        let id_bytes = qid.to_be_bytes();
                        resp[0] = id_bytes[0];
                        resp[1] = id_bytes[1];
                    }
                    Ok(resp)
                }
                Err(_) => Err(ForwardError::LeaderFailed),
            }
        } else {
            // Step 5: LEADER path.
            match forward().await {
                Ok(resp) => {
                    // Compute TTL to cache under.
                    let ttl = if protocol::is_nxdomain(&resp) {
                        Duration::from_secs(
                            protocol::min_ttl_from_response(&resp)
                                .unwrap_or(60)
                                .min(60) as u64,
                        )
                    } else {
                        Duration::from_secs(
                            protocol::min_ttl_from_response(&resp)
                                .unwrap_or(300)
                                .max(1) as u64,
                        )
                    };

                    // Store in cache.
                    self.cache.lock().await.put(question.clone(), resp.clone(), ttl);

                    // Wake followers: remove entry first, then send.
                    let tx = {
                        let mut in_flight = self.in_flight.lock().await;
                        in_flight.remove(&question)
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(Arc::new(resp.clone()));
                    }

                    Ok(resp)
                }
                Err(e) => {
                    // Remove in_flight entry — dropping the Sender wakes followers
                    // with RecvError → ForwardError::LeaderFailed.
                    let mut in_flight = self.in_flight.lock().await;
                    in_flight.remove(&question);
                    Err(ForwardError::Forward(e))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Build a minimal valid A-query for the given name with id=0x1234.
    fn build_query(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: id=0x1234, flags=0x0100 (RD), qdcount=1, rest=0
        buf.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount
        buf.extend_from_slice(&[0x00, 0x00]); // ancount
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root label
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        buf
    }

    /// Build a minimal DNS response for the given query id with a single A RR
    /// carrying `ttl`.
    fn build_response(id: u16, name: &str, ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let id_bytes = id.to_be_bytes();
        buf.extend_from_slice(&[id_bytes[0], id_bytes[1]]); // id
        buf.extend_from_slice(&[0x81, 0x80]);               // flags QR+RD+RA
        buf.extend_from_slice(&[0x00, 0x01]);               // qdcount
        buf.extend_from_slice(&[0x00, 0x00]);               // bytes 6-7 (ignored by parse_header)
        buf.extend_from_slice(&[0x00, 0x01]);               // bytes 8-9 = ancount (parse_header reads here)
        buf.extend_from_slice(&[0x00, 0x00]);               // arcount
        // Question section
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass
        // Answer: compressed ptr to offset 12
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&1u16.to_be_bytes()); // type A
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        buf.extend_from_slice(&[1, 2, 3, 4]);       // rdata
        buf
    }

    // (a) Cache hit: forward called once across 2 sequential same-question resolves.
    #[tokio::test]
    async fn cache_hit_calls_forward_once() {
        let fc = ForwardCache::new(64);
        let counter = Arc::new(AtomicUsize::new(0));
        let query = build_query("example.com");
        let response = build_response(0x1234, "example.com", 300);

        // First resolve — cache miss, forward invoked.
        {
            let c = counter.clone();
            let resp = response.clone();
            let result = fc
                .resolve::<_, _, String>(&query, move || {
                    c.fetch_add(1, Ordering::SeqCst);
                    async move { Ok(resp) }
                })
                .await
                .unwrap();
            // id must match query (0x1234)
            assert_eq!(result[0], 0x12);
            assert_eq!(result[1], 0x34);
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1, "forward must be called on first resolve");

        // Second resolve — cache hit, forward NOT invoked.
        {
            let c = counter.clone();
            let resp = response.clone();
            let result = fc
                .resolve::<_, _, String>(&query, move || {
                    c.fetch_add(1, Ordering::SeqCst);
                    async move { Ok(resp) }
                })
                .await
                .unwrap();
            assert_eq!(result[0], 0x12);
            assert_eq!(result[1], 0x34);
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1, "forward must NOT be called on cache hit");
    }

    // (b) Two concurrent identical resolves call forward exactly once.
    #[tokio::test]
    async fn singleflight_concurrent_calls_forward_once() {
        let fc = Arc::new(ForwardCache::new(64));
        let counter = Arc::new(AtomicUsize::new(0));
        let query = build_query("concurrent.example.com");
        let response = build_response(0x1234, "concurrent.example.com", 300);

        let fc1 = fc.clone();
        let fc2 = fc.clone();
        let c1 = counter.clone();
        let c2 = counter.clone();
        let q1 = query.clone();
        let q2 = query.clone();
        let r1 = response.clone();
        let r2 = response.clone();

        let t1 = tokio::spawn(async move {
            fc1.resolve::<_, _, String>(&q1, move || {
                c1.fetch_add(1, Ordering::SeqCst);
                async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(r1)
                }
            })
            .await
        });

        let t2 = tokio::spawn(async move {
            // Small delay so t1 becomes leader first.
            tokio::time::sleep(Duration::from_millis(5)).await;
            fc2.resolve::<_, _, String>(&q2, move || {
                c2.fetch_add(1, Ordering::SeqCst);
                async move { Ok(r2) }
            })
            .await
        });

        let (res1, res2) = tokio::join!(t1, t2);
        let res1 = res1.unwrap().unwrap();
        let res2 = res2.unwrap().unwrap();

        // Both must return a valid response.
        assert!(res1.len() >= 2);
        assert!(res2.len() >= 2);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "forward must be called exactly once for concurrent identical queries"
        );
    }
}
