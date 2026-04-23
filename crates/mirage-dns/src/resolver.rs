use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::cache::{DnsCache, CacheStats};
use crate::doh::DohClient;
use crate::protocol;

pub struct DnsConfig {
    pub doh_url: String,
    pub http_proxy: Option<String>,
    pub cache_size: usize,
    pub timeout: Duration,
    pub fallback_dns: SocketAddr,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_url: "https://1.1.1.1/dns-query".into(),
            http_proxy: None,
            cache_size: 4096,
            timeout: Duration::from_secs(5),
            fallback_dns: "8.8.8.8:53".parse().unwrap(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("query too short")]
    QueryTooShort,
    #[error("malformed query")]
    MalformedQuery,
    #[error("DoH failed: {0}")]
    Doh(#[from] crate::doh::DohError),
    #[error("fallback DNS failed: {0}")]
    Fallback(String),
    #[error("timeout")]
    Timeout,
}

struct ResolverInner {
    doh: DohClient,
    cache: Mutex<DnsCache>,
    fallback_dns: SocketAddr,
    timeout: Duration,
}

/// Thread-safe DNS resolver with DoH upstream and caching.
/// Clone is cheap (Arc internally).
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<ResolverInner>,
}

impl DnsResolver {
    pub fn new(config: DnsConfig) -> Result<Self, crate::doh::DohError> {
        let doh = DohClient::new(
            &config.doh_url,
            config.http_proxy.as_deref(),
            config.timeout,
        ).map_err(|e| crate::doh::DohError::Http(e))?;

        Ok(Self {
            inner: Arc::new(ResolverInner {
                doh,
                cache: Mutex::new(DnsCache::new(config.cache_size)),
                fallback_dns: config.fallback_dns,
                timeout: config.timeout,
            }),
        })
    }

    /// Resolve a raw DNS query packet. Returns raw DNS response.
    pub async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if query.len() < 12 {
            return Err(DnsError::QueryTooShort);
        }

        let header = protocol::parse_header(query).ok_or(DnsError::MalformedQuery)?;
        let query_id = header.id;

        let (question, _) = match protocol::parse_question(query) {
            Some(q) => q,
            None => return Err(DnsError::MalformedQuery),
        };

        // Cache lookup
        {
            let mut cache = self.inner.cache.lock().await;
            if let Some(cached) = cache.get(&question, query_id) {
                debug!("DNS cache hit: {question}");
                return Ok(cached);
            }
        }

        debug!("DNS cache miss: {question}");

        // DoH query with timeout
        let response = match tokio::time::timeout(
            self.inner.timeout,
            self.inner.doh.query(query),
        ).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                warn!("DoH failed for {question}: {e}, trying fallback");
                return self.fallback_tcp(query, &question, query_id).await;
            }
            Err(_) => {
                warn!("DoH timeout for {question}, trying fallback");
                return self.fallback_tcp(query, &question, query_id).await;
            }
        };

        // Extract TTL and cache
        let ttl = protocol::min_ttl_from_response(&response).unwrap_or(300);
        let is_nx = protocol::is_nxdomain(&response);
        let cache_ttl = if is_nx {
            Duration::from_secs(ttl.min(60) as u64)
        } else {
            Duration::from_secs(ttl as u64)
        };

        {
            let mut cache = self.inner.cache.lock().await;
            cache.put(question, response.clone(), cache_ttl);
        }

        Ok(response)
    }

    async fn fallback_tcp(
        &self,
        query: &[u8],
        question: &protocol::DnsQuestion,
        query_id: u16,
    ) -> Result<Vec<u8>, DnsError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = self.inner.fallback_dns;
        debug!("DNS fallback TCP → {addr} for {question}");

        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| DnsError::Timeout)?
        .map_err(|e| DnsError::Fallback(format!("connect {addr}: {e}")))?;

        // DNS-over-TCP: 2-byte length prefix
        let len_prefix = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await
            .map_err(|e| DnsError::Fallback(format!("write: {e}")))?;
        stream.write_all(query).await
            .map_err(|e| DnsError::Fallback(format!("write: {e}")))?;

        let mut resp_len_bytes = [0u8; 2];
        stream.read_exact(&mut resp_len_bytes).await
            .map_err(|e| DnsError::Fallback(format!("read len: {e}")))?;
        let resp_len = u16::from_be_bytes(resp_len_bytes) as usize;

        if resp_len < 12 || resp_len > 65535 {
            return Err(DnsError::Fallback(format!("bad response length: {resp_len}")));
        }

        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await
            .map_err(|e| DnsError::Fallback(format!("read body: {e}")))?;

        // Cache fallback response too
        let ttl = protocol::min_ttl_from_response(&resp).unwrap_or(60);
        let cache_ttl = if protocol::is_nxdomain(&resp) {
            Duration::from_secs(ttl.min(60) as u64)
        } else {
            Duration::from_secs(ttl as u64)
        };

        {
            let mut cache = self.inner.cache.lock().await;
            cache.put(question.clone(), resp.clone(), cache_ttl);
        }

        // Ensure response ID matches query
        if resp.len() >= 2 {
            let id_bytes = query_id.to_be_bytes();
            resp[0] = id_bytes[0];
            resp[1] = id_bytes[1];
        }

        info!("DNS fallback success: {question} ({resp_len} bytes)");
        Ok(resp)
    }

    pub async fn cache_stats(&self) -> CacheStats {
        self.inner.cache.lock().await.stats()
    }
}
