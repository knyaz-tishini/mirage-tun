use clap::Parser;
use mirage_tun_core::policy::{PolicyConfigRequest, PolicyDecision, PolicyRule};
use mirage_tun_core::stack_config::{ChainDnsConfig, ChainEntry, StackConfig};
use mirage_tun_macos::{api, MacosTunStack};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "mirage2tun", version, about = "Mirage TUN adapter for macOS")]
struct Cli {
    /// Path to stack config JSON file
    #[arg(long)]
    config: String,

    /// Log level filter (e.g. info, debug, warn)
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── JSON-deserializable config (StackConfig lacks Deserialize derive) ─────────

#[derive(Deserialize)]
struct BinConfig {
    tun_addr: String,
    #[serde(default)]
    tun_addr_v6: Option<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default)]
    chains: Vec<BinChainEntry>,
    #[serde(default)]
    chain_dns: Vec<BinChainDnsConfig>,
    #[serde(default = "default_true")]
    kill_switch: bool,
    #[serde(default)]
    relay_addrs: Vec<IpAddr>,
    #[serde(default = "default_dns_upstream")]
    dns_upstream: SocketAddr,
    #[serde(default = "default_ttl")]
    dns_cache_ttl_secs: u64,
    #[serde(default = "default_cache_max")]
    dns_cache_max: usize,
    #[serde(default = "default_concurrency")]
    dns_concurrency: usize,
    #[serde(default = "default_concurrency")]
    socks5_concurrency: usize,
    #[serde(default)]
    per_chain_tun: bool,
    #[serde(default = "default_api_bind")]
    api_bind: String,
    /// Full routing policy (CIDR/domain/port/app → chain|bypass). Absent = all
    /// flows use the first chain (legacy single-wire). Phase 2a: Bypass DestCidr
    /// rules form the bypass plane.
    #[serde(default)]
    policy: Option<PolicyConfigRequest>,
    /// Convenience shortcut for the common "байпас канал" case — CIDRs/domains
    /// to egress DIRECT (real NIC). Appended as Bypass policy rules.
    #[serde(default)]
    bypass: BypassShortcut,
}

#[derive(Deserialize)]
struct BinChainEntry {
    name: String,
    socks5_addr: SocketAddr,
}

#[derive(Deserialize, Default)]
struct BypassShortcut {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
}

/// Merge the optional explicit policy with the bypass-shortcut CIDRs/domains.
fn build_policy(base: Option<PolicyConfigRequest>, bypass: &BypassShortcut) -> PolicyConfigRequest {
    let mut req = base.unwrap_or_else(|| PolicyConfigRequest {
        rules: vec![],
        default_action: PolicyDecision::default_chain(),
    });
    for cidr in &bypass.cidrs {
        req.rules.push(PolicyRule::DestCidr {
            cidr: cidr.clone(),
            action: PolicyDecision::Bypass,
        });
    }
    for domain in &bypass.domains {
        req.rules.push(PolicyRule::DestDomain {
            domain: domain.clone(),
            action: PolicyDecision::Bypass,
        });
    }
    req
}

#[derive(Deserialize)]
struct BinChainDnsConfig {
    chain_name: String,
    servers: Vec<IpAddr>,
}

fn default_api_bind() -> String { "127.0.0.1:19485".to_string() }
fn default_mtu() -> u16 { 1280 } // onion+AEAD+camo headroom; 1500 = PMTUD blackhole on the onion handshake
fn default_true() -> bool { true }
fn default_dns_upstream() -> SocketAddr { "8.8.8.8:53".parse().expect("static addr") }
fn default_ttl() -> u64 { 300 }
fn default_cache_max() -> usize { 4096 }
fn default_concurrency() -> usize { 64 }

impl From<BinConfig> for StackConfig {
    fn from(b: BinConfig) -> Self {
        StackConfig {
            tun_addr: b.tun_addr,
            tun_addr_v6: b.tun_addr_v6,
            mtu: b.mtu,
            chains: b.chains.into_iter().map(|c| ChainEntry { name: c.name, socks5_addr: c.socks5_addr }).collect(),
            policy: build_policy(b.policy, &b.bypass),
            chain_dns: b.chain_dns.into_iter().map(|d| ChainDnsConfig { chain_name: d.chain_name, servers: d.servers }).collect(),
            kill_switch: b.kill_switch,
            relay_addrs: b.relay_addrs,
            dns_upstream: b.dns_upstream,
            dns_cache_ttl_secs: b.dns_cache_ttl_secs,
            dns_cache_max: b.dns_cache_max,
            dns_concurrency: b.dns_concurrency,
            socks5_concurrency: b.socks5_concurrency,
            per_chain_tun: b.per_chain_tun,
        }
    }
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        tracing::error!(location = %location, message = %msg, "panic — process exiting for respawn");
        std::thread::sleep(std::time::Duration::from_millis(100));
        std::process::exit(1);
    }));

    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed: system resources exhausted");

    rt.block_on(async move {
        let raw = std::fs::read_to_string(&cli.config).unwrap_or_else(|e| {
            tracing::error!(path = %cli.config, err = %e, "failed to read config");
            std::process::exit(1);
        });

        let bin_cfg: BinConfig = serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::error!(err = %e, "failed to parse config");
            std::process::exit(1);
        });

        let api_bind_str = bin_cfg.api_bind.clone();
        let cfg: StackConfig = bin_cfg.into();

        let cancel = CancellationToken::new();
        let cancel_ctrl = cancel.clone();

        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    tracing::info!("SIGINT received — shutting down");
                    cancel_ctrl.cancel();
                }
                Err(e) => {
                    tracing::error!(err = %e, "ctrl-c handler error");
                    cancel_ctrl.cancel();
                }
            }
        });

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let cancel_term = cancel.clone();
            let mut sigterm = signal(SignalKind::terminate())
                .expect("SIGTERM handler registration failed: system resources exhausted");
            tokio::spawn(async move {
                sigterm.recv().await;
                tracing::info!("SIGTERM received — shutting down");
                cancel_term.cancel();
            });
        }

        match MacosTunStack::start_with_metrics(cfg, cancel.clone()).await {
            Ok((_handle, chain_metrics, chain_registry)) => {
                let api_bind: SocketAddr = api_bind_str.parse().unwrap_or_else(|e| {
                    tracing::error!(val = %api_bind_str, err = %e, "invalid api_bind — using default");
                    "127.0.0.1:19485".parse().expect("hardcoded fallback is valid")
                });
                tokio::spawn(api::serve(api_bind, chain_metrics, chain_registry, cancel.child_token()));

                cancel.cancelled().await;
                tracing::info!("cancelled — exiting");
            }
            Err(e) => {
                tracing::error!(err = %e, "stack start failed");
                std::process::exit(1);
            }
        }
    });
}
