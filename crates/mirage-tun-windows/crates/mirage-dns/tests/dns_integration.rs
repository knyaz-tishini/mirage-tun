//! Integration tests for mirage-dns.
//! Safe to run without VPN — uses public DNS servers directly.

use mirage_dns::{DnsConfig, DnsResolver};
use std::time::Duration;

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Header: id=0xABCD, flags=0x0100 (RD), qdcount=1
    buf.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00]);
    buf.extend_from_slice(&[0x00, 0x01]); // qdcount
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar count
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN class
    buf
}

/// Test: DNS fallback (direct TCP to 8.8.8.8) works without any proxy
#[tokio::test]
async fn fallback_dns_resolves_google() {
    let config = DnsConfig {
        doh_url: "https://127.0.0.1:1/dns-query".into(), // intentionally broken DoH
        http_proxy: None,
        cache_size: 100,
        timeout: Duration::from_secs(2),
        fallback_dns: "8.8.8.8:53".parse().unwrap(),
    };
    let resolver = DnsResolver::new(config).unwrap();
    let query = build_dns_query("google.com", 1); // A record
    let response = resolver.resolve(&query).await.unwrap();

    // Verify it's a valid DNS response
    assert!(response.len() >= 12);
    // Response ID should match query ID
    assert_eq!(response[0], 0xAB);
    assert_eq!(response[1], 0xCD);
    // QR bit should be set (response)
    assert!(response[2] & 0x80 != 0);
    // RCODE should be 0 (no error)
    assert_eq!(response[3] & 0x0F, 0);
}

/// Test: cache works — second query is instant
#[tokio::test]
async fn cache_serves_second_query() {
    let config = DnsConfig {
        doh_url: "https://127.0.0.1:1/dns-query".into(), // broken DoH → forces fallback
        http_proxy: None,
        cache_size: 100,
        timeout: Duration::from_secs(2),
        fallback_dns: "8.8.8.8:53".parse().unwrap(),
    };
    let resolver = DnsResolver::new(config).unwrap();
    let query = build_dns_query("example.com", 1);

    // First query — goes to fallback
    let _resp1 = resolver.resolve(&query).await.unwrap();

    // Second query — should be cached (different ID to prove cache rewrites ID)
    let mut query2 = query.clone();
    query2[0] = 0x12;
    query2[1] = 0x34;

    let start = std::time::Instant::now();
    let resp2 = resolver.resolve(&query2).await.unwrap();
    let elapsed = start.elapsed();

    // Cache hit should be < 1ms (definitely < 50ms)
    assert!(elapsed < Duration::from_millis(50), "cache hit took {:?}", elapsed);
    // Response ID should match second query's ID
    assert_eq!(resp2[0], 0x12);
    assert_eq!(resp2[1], 0x34);
}

/// Test: NXDOMAIN is cached
#[tokio::test]
async fn nxdomain_is_cached() {
    let config = DnsConfig {
        doh_url: "https://127.0.0.1:1/dns-query".into(),
        http_proxy: None,
        cache_size: 100,
        timeout: Duration::from_secs(2),
        fallback_dns: "8.8.8.8:53".parse().unwrap(),
    };
    let resolver = DnsResolver::new(config).unwrap();
    let query = build_dns_query("thisdomain.definitely.does.not.exist.example.invalid", 1);

    let resp1 = resolver.resolve(&query).await.unwrap();
    // RCODE should be NXDOMAIN (3)
    assert_eq!(resp1[3] & 0x0F, 3, "expected NXDOMAIN");

    // Second query — should be cached
    let start = std::time::Instant::now();
    let _resp2 = resolver.resolve(&query).await.unwrap();
    assert!(start.elapsed() < Duration::from_millis(50));
}

/// Test: malformed query returns error
#[tokio::test]
async fn malformed_query_rejected() {
    let config = DnsConfig::default();
    let resolver = DnsResolver::new(config).unwrap();

    // Too short
    assert!(resolver.resolve(&[0; 5]).await.is_err());
    // Empty
    assert!(resolver.resolve(&[]).await.is_err());
}
