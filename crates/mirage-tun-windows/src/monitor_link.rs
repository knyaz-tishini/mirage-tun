//! Internal MonitorLink for headless mirage2tun deployments.
//!
//! When `tun.json` contains a `monitor_url` field, mirage2tun spawns this
//! background task.  It connects to mirage2monitor (WebSocket-first, HTTP-poll
//! fallback) and on every config push translates the healthy chain list into
//! the same `ChainMap` that `POST /chains/update` produces, then writes it
//! directly into the shared [`ChainRegistry`].
//!
//! This is a self-contained copy of the monitor_link logic from
//! `mirage-client-core`.  A cross-workspace path dep was not feasible because
//! `mirage-client-core` pulls in the entire mirage2app workspace
//! (`mirage-core`, `mirage-mux`, `mirage-protocol`, …) which are not
//! available in mirage2tun's separate Cargo workspace.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, Message},
};
use tracing::{debug, info, warn};

use crate::chains::{ChainEntry, ChainRegistry};

// ── Wire format received from mirage2monitor ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct ConfigResponse {
    version: u64,
    chains: Vec<WireChain>,
    #[serde(default = "default_poll_interval")]
    monitor_poll_interval_secs: u64,
    /// Dynamic monitor URL list pushed by the LM (peers + this LM's public URL).
    /// Sentry/probe LM endpoints in this list are auto-bypassed by the TUN
    /// adapter so management traffic never re-enters the tunnel.
    #[serde(default)]
    peer_lm_urls: Vec<String>,
}

fn default_poll_interval() -> u64 {
    30
}

/// Single chain entry as sent by mirage2monitor's `/relay/clients/config`.
#[derive(Debug, Deserialize)]
struct WireChain {
    /// Logical chain name (used as key in ChainRegistry).
    #[serde(alias = "chain_id")]
    name: String,
    /// SOCKS5 listener address — either `socks5_bind` or a best-effort field.
    /// The monitor sends `socks5_bind` for chains that have a local listener.
    #[serde(default)]
    socks5_bind: Option<String>,
    /// Fallback: direct L1 node address (used when `socks5_bind` is absent).
    #[serde(default)]
    socks5_addr: Option<String>,
    /// Whether the monitor considers this chain healthy.
    #[serde(default = "wire_chain_default_healthy")]
    healthy: bool,
    /// Optional per-chain DNS upstream override.
    #[serde(default)]
    dns_upstream: Option<String>,
}

fn wire_chain_default_healthy() -> bool {
    true
}

impl WireChain {
    /// Resolve to a SOCKS5 `SocketAddr`.  Returns `None` when neither
    /// `socks5_bind` nor `socks5_addr` is a parseable address.
    fn socks5_socket_addr(&self) -> Option<SocketAddr> {
        self.socks5_bind
            .as_deref()
            .or(self.socks5_addr.as_deref())
            .and_then(|s| s.parse().ok())
    }

    fn dns_upstream_addr(&self) -> Option<SocketAddr> {
        self.dns_upstream.as_deref().and_then(|s| s.parse().ok())
    }
}

// ── Registration / heartbeat bodies ──────────────────────────────────────────

#[derive(Debug, Serialize)]
struct RegisterBody {
    os: &'static str,
    version: &'static str,
    supported_transports: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    client_id: String,
    #[serde(default = "default_poll_interval")]
    monitor_poll_interval_secs: u64,
}

#[derive(Debug, Serialize)]
struct HeartbeatBody {
    active_chains: u32,
}

// ── WS state ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsState {
    Active,
    FallbackPoll,
}

impl std::fmt::Display for WsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsState::Active => f.write_str("Active"),
            WsState::FallbackPoll => f.write_str("FallbackPoll"),
        }
    }
}

// ── MonitorLink ───────────────────────────────────────────────────────────────

/// Background task that syncs chain config from mirage2monitor into the local
/// [`ChainRegistry`].
pub struct MonitorLink {
    monitor_url: String,
    monitor_api_key: Option<String>,
    client_id: Mutex<Option<String>>,
    http: reqwest::Client,
    config_version: AtomicU64,
    poll_interval_secs: AtomicU64,
    /// Sends `Some(map)` every time a new config is received.
    chain_tx: watch::Sender<Option<HashMap<String, ChainEntry>>>,
    /// Sends the latest `peer_lm_urls` host list so the TUN can keep its
    /// bypass route table additive with every config push.  Hosts may be
    /// either parseable IP literals or DNS names (caller resolves).
    peer_lm_tx: watch::Sender<Vec<String>>,
}

impl MonitorLink {
    /// Build a new `MonitorLink` and return a watch receiver for chain maps.
    pub fn new(
        monitor_url: String,
        monitor_api_key: Option<String>,
    ) -> (Arc<Self>, watch::Receiver<Option<HashMap<String, ChainEntry>>>) {
        let (chain_tx, chain_rx) = watch::channel(None);
        let (peer_lm_tx, _peer_lm_rx) = watch::channel(Vec::new());

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest::Client construction is infallible with valid settings");

        let link = Arc::new(Self {
            monitor_url,
            monitor_api_key,
            client_id: Mutex::new(None),
            http,
            config_version: AtomicU64::new(0),
            poll_interval_secs: AtomicU64::new(30),
            chain_tx,
            peer_lm_tx,
        });

        (link, chain_rx)
    }

    /// Subscribe to the host list extracted from `peer_lm_urls` on every
    /// config push.  Hosts may be IP literals or DNS names — consumers
    /// resolve and feed them into the routing bypass list.
    pub fn subscribe_peer_lm_hosts(&self) -> watch::Receiver<Vec<String>> {
        self.peer_lm_tx.subscribe()
    }

    /// Spawn the background loop.
    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let link = Arc::clone(self);
        tokio::spawn(async move { link.run().await })
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    async fn run(&self) {
        self.register().await;

        info!("monitor_link(tun): state → {} (initial WebSocket attempt)", WsState::Active);
        match self.run_ws_loop().await {
            Ok(()) => info!("monitor_link(tun): WebSocket closed cleanly, switching to FallbackPoll"),
            Err(e) => warn!("monitor_link(tun): WebSocket failed ({e}), switching to FallbackPoll"),
        }

        info!("monitor_link(tun): state → {}", WsState::FallbackPoll);
        let poll_secs = self.poll_interval_secs.load(Ordering::Relaxed);
        let mut poll_interval = tokio::time::interval(Duration::from_secs(poll_secs));
        let ws_retry_interval = Duration::from_secs(5 * 60);
        let mut ws_retry_deadline = tokio::time::Instant::now() + ws_retry_interval;

        loop {
            tokio::select! {
                _ = poll_interval.tick() => {
                    self.poll_config().await;
                    self.send_heartbeat().await;
                }
                _ = tokio::time::sleep_until(ws_retry_deadline) => {
                    info!("monitor_link(tun): state → {} (retry WebSocket)", WsState::Active);
                    match self.run_ws_loop().await {
                        Ok(()) => info!("monitor_link(tun): WebSocket closed, back to FallbackPoll"),
                        Err(e) => warn!("monitor_link(tun): WebSocket retry failed ({e}), staying in FallbackPoll"),
                    }
                    info!("monitor_link(tun): state → {}", WsState::FallbackPoll);
                    ws_retry_deadline = tokio::time::Instant::now() + ws_retry_interval;
                }
            }
        }
    }

    async fn run_ws_loop(&self) -> Result<(), String> {
        use futures::StreamExt;

        let ws_url = http_to_ws_url(&self.monitor_url);
        let subscribe_url = format!("{ws_url}/relay/clients/subscribe");

        let mut req = subscribe_url
            .into_client_request()
            .map_err(|e| format!("build WS request: {e}"))?;

        if let Some(key) = &self.monitor_api_key {
            let header_val = format!("Bearer {key}")
                .parse::<tokio_tungstenite::tungstenite::http::HeaderValue>()
                .map_err(|e| format!("invalid auth header: {e}"))?;
            req.headers_mut().insert(
                tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
                header_val,
            );
        }

        let (ws_stream, _) = connect_async_tls_with_config(req, None, false, None)
            .await
            .map_err(|e| format!("WS upgrade failed: {e}"))?;

        info!("monitor_link(tun): state → Connected (WebSocket)");

        let (_write, mut read) = ws_stream.split();

        loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<ConfigResponse>(&text) {
                        Ok(cfg) => {
                            debug!(
                                version = cfg.version,
                                chains = cfg.chains.len(),
                                "monitor_link(tun): WS config push received"
                            );
                            self.apply_config(cfg);
                        }
                        Err(e) => {
                            warn!("monitor_link(tun): WS frame parse error: {e}");
                        }
                    }
                }
                Some(Ok(Message::Ping(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    info!("monitor_link(tun): WebSocket closed by server");
                    return Ok(());
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    return Err(format!("WS stream error: {e}"));
                }
            }
        }
    }

    fn apply_config(&self, cfg: ConfigResponse) {
        self.config_version.store(cfg.version, Ordering::Relaxed);
        self.poll_interval_secs
            .store(cfg.monitor_poll_interval_secs, Ordering::Relaxed);

        // Extract the host portion of every peer LM URL and forward to the
        // routing bypass watcher.  We include the (probably already-known)
        // self URL on purpose — last-writer-wins on the routing side, and
        // an extra duplicate is harmless.
        let peer_hosts: Vec<String> = cfg
            .peer_lm_urls
            .iter()
            .filter_map(|u| extract_host(u))
            .collect();
        let _ = self.peer_lm_tx.send(peer_hosts);

        let map: HashMap<String, ChainEntry> = cfg
            .chains
            .into_iter()
            .filter(|c| c.healthy)
            .filter_map(|c| {
                let socks5_addr = c.socks5_socket_addr()?;
                let dns_upstream = c.dns_upstream_addr();
                Some((c.name.clone(), ChainEntry { chain_id: c.name.clone(), socks5_addr, dns_upstream }))
            })
            .collect();

        debug!(chains = map.len(), "monitor_link(tun): applying chain map");
        let _ = self.chain_tx.send(Some(map));
    }

    async fn register(&self) {
        let url = format!("{}/relay/clients", self.monitor_url);
        let body = RegisterBody {
            os: std::env::consts::OS,
            version: env!("CARGO_PKG_VERSION"),
            supported_transports: vec!["tcp", "websocket"],
        };

        let mut req = self.http.post(&url).json(&body);
        if let Some(key) = &self.monitor_api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<RegisterResponse>().await {
                    Ok(reg) => {
                        debug!(client_id = %reg.client_id, "monitor_link(tun): registered");
                        self.poll_interval_secs
                            .store(reg.monitor_poll_interval_secs, Ordering::Relaxed);
                        *self.client_id.lock().await = Some(reg.client_id);
                        self.poll_config().await;
                    }
                    Err(e) => {
                        warn!(status = %status, "monitor_link(tun): register: failed to parse response: {e}");
                    }
                }
            }
            Err(e) => {
                warn!("monitor_link(tun): register: request failed: {e}");
            }
        }
    }

    async fn poll_config(&self) {
        let url = format!("{}/relay/clients/config", self.monitor_url);
        let current_version = self.config_version.load(Ordering::Relaxed);

        let mut req = self
            .http
            .get(&url)
            .header("If-None-Match", current_version.to_string());
        if let Some(key) = &self.monitor_api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_MODIFIED {
                    debug!(version = current_version, "monitor_link(tun): config unchanged (304)");
                    return;
                }
                if !status.is_success() {
                    warn!(status = %status, "monitor_link(tun): config poll: unexpected status");
                    return;
                }
                match resp.json::<ConfigResponse>().await {
                    Ok(cfg) => {
                        debug!(
                            version = cfg.version,
                            chains = cfg.chains.len(),
                            "monitor_link(tun): config updated (HTTP poll)"
                        );
                        self.apply_config(cfg);
                    }
                    Err(e) => {
                        warn!("monitor_link(tun): config poll: failed to parse response: {e}");
                    }
                }
            }
            Err(e) => {
                warn!("monitor_link(tun): config poll: request failed: {e}");
            }
        }
    }

    async fn send_heartbeat(&self) {
        let client_id = {
            let guard = self.client_id.lock().await;
            match guard.as_deref() {
                Some(id) => id.to_owned(),
                None => return,
            }
        };

        let url = format!(
            "{}/relay/clients/{}/heartbeat",
            self.monitor_url, client_id
        );
        let active_chains = self
            .config_version
            .load(Ordering::Relaxed)
            .min(u32::MAX as u64) as u32;
        let body = HeartbeatBody { active_chains };

        let mut req = self.http.post(&url).json(&body);
        if let Some(key) = &self.monitor_api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        if let Err(e) = req.send().await {
            warn!("monitor_link(tun): heartbeat: request failed: {e}");
        }
    }
}

// ── Watcher task ──────────────────────────────────────────────────────────────

/// Spawn a task that reads chain maps from `chain_rx` and writes them directly
/// into `registry`.  Both paths (HTTP handler and MonitorLink) share the same
/// `Arc<ChainRegistry>` — last writer wins.
pub fn spawn_chain_watcher(
    mut chain_rx: watch::Receiver<Option<HashMap<String, ChainEntry>>>,
    registry: Arc<ChainRegistry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while chain_rx.changed().await.is_ok() {
            // Clone out of the borrow guard before any await — watch::Ref is
            // not Send and must not be held across an await point.
            let map = chain_rx.borrow().clone();
            if let Some(map) = map {
                let count = map.len();
                registry.update(map).await;
                info!("monitor_link(tun): chain registry updated: {count} healthy chains");
            }
        }
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn http_to_ws_url(url: &str) -> String {
    if url.starts_with("https://") {
        format!("wss://{}", &url["https://".len()..])
    } else if url.starts_with("http://") {
        format!("ws://{}", &url["http://".len()..])
    } else {
        url.to_owned()
    }
}

/// Extract the host part of a URL like `http://1.2.3.4:19410` →
/// `"1.2.3.4"`, or `https://lm.example.com:19443` → `"lm.example.com"`.
/// Bracketed IPv6 hosts (`[::1]`) are returned without the brackets.
/// Returns `None` for unparseable input.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let after_host = after_scheme.split('/').next().unwrap_or(after_scheme);
    let after_userinfo = after_host.rsplit_once('@').map_or(after_host, |(_, r)| r);
    let host = if let Some(rest) = after_userinfo.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h)?.to_owned()
    } else {
        after_userinfo
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(after_userinfo)
            .to_owned()
    };
    if host.is_empty() { None } else { Some(host) }
}

/// Spawn a background task that watches `peer_lm_rx` for host-list updates,
/// resolves them to IPs (DNS lookup per name), and asks `routing` to add a
/// bypass route for any IP not already present in `routing`'s bypass set.
///
/// The list is **additive** — we never remove a previously added bypass,
/// matching the existing `relay_addrs` behaviour.  Restart the service if
/// you need to drop a stale bypass.
pub fn spawn_peer_lm_bypass_watcher(
    mut peer_lm_rx: watch::Receiver<Vec<String>>,
    service: Arc<tokio::sync::Mutex<crate::state::ServiceState>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while peer_lm_rx.changed().await.is_ok() {
            let hosts = peer_lm_rx.borrow().clone();
            if hosts.is_empty() {
                continue;
            }
            let mut new_ips: Vec<IpAddr> = Vec::new();
            for h in &hosts {
                if let Ok(ip) = h.parse::<IpAddr>() {
                    new_ips.push(ip);
                    continue;
                }
                // DNS resolve via the OS resolver (blocking, but cheap).
                let host = h.clone();
                match tokio::task::spawn_blocking(move || {
                    use std::net::ToSocketAddrs;
                    (host.as_str(), 0u16)
                        .to_socket_addrs()
                        .map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())
                })
                .await
                {
                    Ok(Ok(ips)) => new_ips.extend(ips),
                    Ok(Err(e)) => warn!(host = %h, "peer_lm bypass: resolve failed: {e}"),
                    Err(e) => warn!("peer_lm bypass: resolver task join failed: {e}"),
                }
            }
            if new_ips.is_empty() {
                continue;
            }

            let mut s = service.lock().await;
            // Skip if TUN isn't active yet — the next config push will retry.
            if s.tun_phase != crate::state::TunPhase::TunActive {
                continue;
            }
            let gateway = s.original_gateway.clone();
            let if_index = s.if_index;
            // Filter out IPs already in the bypass set so we don't re-run
            // netsh for each duplicate.
            let mut added = 0_usize;
            for ip in new_ips {
                if s.bypass_addrs.iter().any(|existing| *existing == ip) {
                    continue;
                }
                if let Err(e) =
                    crate::routing::add_runtime_bypass(ip, gateway.as_deref(), if_index).await
                {
                    warn!(%ip, "peer_lm bypass: add failed: {e}");
                    continue;
                }
                s.bypass_addrs.push(ip);
                added += 1;
            }
            if added > 0 {
                info!("peer_lm bypass: added {added} new bypass route(s)");
            }
        }
    })
}
