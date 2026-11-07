use std::time::Duration;
use reqwest::Client;
use tracing::{debug, warn};

pub struct DohClient {
    client: Client,
    url: String,
}

impl DohClient {
    pub fn new(doh_url: &str, http_proxy: Option<&str>, timeout: Duration) -> Result<Self, reqwest::Error> {
        let mut builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(4)
            .http2_prior_knowledge()
            .use_rustls_tls()
            .no_hickory_dns();

        if let Some(proxy_url) = http_proxy {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        Ok(Self {
            client,
            url: doh_url.to_string(),
        })
    }

    /// Send a DNS query via DoH (RFC 8484 POST with application/dns-message).
    pub async fn query(&self, dns_query: &[u8]) -> Result<Vec<u8>, DohError> {
        debug!("DoH: sending {} bytes to {}", dns_query.len(), self.url);

        let resp = self.client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_query.to_vec())
            .send()
            .await
            .map_err(DohError::Http)?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!("DoH: HTTP {status} from {}: {body}", self.url);
            return Err(DohError::BadStatus(status.as_u16()));
        }

        let bytes = resp.bytes().await.map_err(DohError::Http)?;
        debug!("DoH: received {} bytes", bytes.len());

        if bytes.len() < 12 {
            return Err(DohError::TooShort(bytes.len()));
        }

        Ok(bytes.to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DohError {
    #[error("HTTP error: {0}")]
    Http(reqwest::Error),
    #[error("DoH server returned HTTP {0}")]
    BadStatus(u16),
    #[error("response too short ({0} bytes)")]
    TooShort(usize),
}
