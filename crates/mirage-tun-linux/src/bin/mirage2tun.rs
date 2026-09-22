//! `mirage2tun` service binary for Linux.
//!
//! Shape (CLI, config-file-at-startup, panic hook, signal handling, control
//! API) is modelled on `mirage-tun-macos/src/bin/mirage2tun.rs` — a foreground
//! process that reads a JSON config, brings the tunnel up, and runs until
//! SIGINT/SIGTERM, rather than Windows' service-manager + `/tun/start`
//! start/stop API (there is no Linux equivalent of the SCM here).
//!
//! What this binary drives, from `mirage-tun-linux`'s own library:
//!   - `LinuxTunStack::start_with_cleanup` — opens `/dev/net/tun`, configures
//!     the address/MTU, installs wg-quick-style policy routing
//!     (`LinuxRouting`), installs the nft/iptables REDIRECT + best-effort
//!     per-process eBPF firewall (`LinuxFirewall`), and pushes DNS
//!     (`LinuxDns`). All four are torn down on cancellation, and this binary
//!     awaits that teardown before exiting (see `run` below).
//!   - The returned `LinuxKernelTcpAcceptor` / `LinuxKernelUdpSocket` are
//!     *real* — per `mirage_tun_core::traits::TcpAcceptor`'s own doc comment,
//!     kernel platforms hand back a live acceptor for the consumer to drive.
//!     This binary is that consumer: `tcp_forward_loop` accepts each
//!     REDIRECT'd connection, resolves it via the policy engine, and forwards
//!     it either through a SOCKS5 chain (RFC 1928, no-auth CONNECT) or
//!     direct-dials it for `Bypass` decisions — both dial paths mark the
//!     outbound socket with `SO_MARK = BYPASS_FWMARK` (`routing::BYPASS_FWMARK`,
//!     declared but previously unused by any caller) so the policy-routing
//!     table sends the tunnel's own egress out the real NIC instead of
//!     looping back into the TUN device.
//!
//! What is NOT wired here (left unreachable rather than faked):
//!   - UDP-to-SOCKS5 relay. `LinuxKernelUdpSocket` only parses raw IP/UDP
//!     packets off the TUN fd (see `kernel_udp.rs`) — there is no SOCKS5 UDP
//!     ASSOCIATE client in this crate (unlike `mirage-tun-windows/udp_socks5.rs`
//!     or `mirage-tun-macos/udp_forward.rs`, both dedicated ~240-line modules).
//!     `drain_udp_unimplemented` logs this plainly once and drops every
//!     datagram — including UDP-based DNS through the tunnel, which will not
//!     resolve. TCP flows are unaffected.
//!   - Per-process plane enforcement (`PlatformExecutor::enforce_flow`,
//!     T3 eBPF-per-cgroup kill-switch in `firewall.rs`). `LinuxFirewall::activate`
//!     already loads and arms the eBPF program best-effort, but nothing in this
//!     binary calls `enforce_flow` per accepted flow — that needs a
//!     `PlaneEngine` fed by a per-process policy surface this config format
//!     does not expose yet.
//!   - `tun_addr_v6` (IPv6 dual-stack) and `per_chain_tun` (isolated TUN per
//!     chain) — neither is implemented by `LinuxTunStack`/`LinuxTunDevice`
//!     today. The former degrades to a startup warning (IPv4-only), the
//!     latter is a hard startup refusal (see `run` below) — starting anyway
//!     would silently give a weaker isolation guarantee than requested.
//!   - Live re-install of policy-driven bypass CIDRs into the firewall/routing
//!     layer on `/policy/set` (see `api.rs` module doc comment) — the new
//!     policy takes effect for the TCP forward loop's next connection, but
//!     `LinuxFirewall`/`LinuxRouting` have no live diff-apply method to call.
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use clap::Parser;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use mirage_tun_core::chains::{ChainConfig, ChainProtocol, ChainRegistry};
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::policy::{
    CompiledPolicy, PolicyConfigRequest, PolicyDecision, PolicyEngine, PolicyRule,
};
use mirage_tun_core::stack_config::{ChainDnsConfig, ChainEntry as StackChainEntry, StackConfig};
use mirage_tun_core::traits::{TcpAcceptor, UdpSocket as CoreUdpSocket};
use mirage_tun_linux::kernel_tcp::LinuxKernelTcpAcceptor;
use mirage_tun_linux::kernel_udp::LinuxKernelUdpSocket;
use mirage_tun_linux::{api, LinuxTunStack};

#[derive(Parser)]
#[command(name = "mirage2tun", version, about = "Mirage TUN adapter for Linux")]
struct Cli {
    /// Path to stack config JSON file.
    #[arg(long)]
    config: String,

    /// Log level filter (e.g. info, debug, warn).
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── JSON-deserializable config (StackConfig lacks Deserialize derive) ─────────

#[derive(Deserialize)]
struct BinConfig {
    #[serde(default = "default_tun_name")]
    tun_name: String,
    tun_addr: String,
    /// Accepted for config compatibility with the macOS/Windows config shape.
    /// Not applied — see the module doc comment.
    #[serde(default)]
    tun_addr_v6: Option<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default)]
    chains: Vec<BinChainEntry>,
    #[serde(default)]
    chain_dns: Vec<BinChainDnsConfig>,
    #[serde(default)]
    relay_addrs: Vec<std::net::IpAddr>,
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
    /// Not implemented — see the module doc comment. `true` is a hard refusal.
    #[serde(default)]
    per_chain_tun: bool,
    #[serde(default = "default_api_bind")]
    api_bind: String,
    /// Optional Bearer token required on all guarded control-API routes.
    #[serde(default)]
    api_key: Option<String>,
    /// Full routing policy (CIDR/domain/port/app → chain|bypass). Absent = all
    /// flows use the first configured chain (legacy single-wire).
    #[serde(default)]
    policy: Option<PolicyConfigRequest>,
    /// Convenience shortcut for the common "bypass channel" case — CIDRs/domains
    /// to egress direct (real NIC). Appended as Bypass policy rules.
    #[serde(default)]
    bypass: BypassShortcut,
}

#[derive(Deserialize)]
struct BinChainEntry {
    name: String,
    socks5_addr: SocketAddr,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    nature: mirage_tun_core::policy::WireNature,
}

#[derive(Deserialize)]
struct BinChainDnsConfig {
    chain_name: String,
    servers: Vec<std::net::IpAddr>,
}

#[derive(Deserialize, Default)]
struct BypassShortcut {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
}

fn build_policy(base: Option<PolicyConfigRequest>, bypass: &BypassShortcut) -> PolicyConfigRequest {
    let mut req = base.unwrap_or_else(|| PolicyConfigRequest {
        rules: vec![],
        default_action: PolicyDecision::default_chain(),
    });
    for cidr in &bypass.cidrs {
        req.rules.push(PolicyRule::DestCidr {
            cidr: cidr.clone(),
            action: PolicyDecision::Bypass,
            failure_policy: Default::default(),
            wire_class: Default::default(),
        });
    }
    for domain in &bypass.domains {
        req.rules.push(PolicyRule::DestDomain {
            domain: domain.clone(),
            action: PolicyDecision::Bypass,
            failure_policy: Default::default(),
            wire_class: Default::default(),
        });
    }
    req
}

fn default_tun_name() -> String { "tun0".to_owned() }
fn default_mtu() -> u16 { 1280 } // onion+AEAD+camo headroom; 1500 = PMTUD blackhole on the onion handshake
fn default_api_bind() -> String { "127.0.0.1:19485".to_string() }
fn default_dns_upstream() -> SocketAddr { "8.8.8.8:53".parse().expect("static addr") }
fn default_ttl() -> u64 { 300 }
fn default_cache_max() -> usize { 4096 }
fn default_concurrency() -> usize { 64 }

impl From<BinConfig> for StackConfig {
    fn from(b: BinConfig) -> Self {
        StackConfig {
            tun_name: b.tun_name,
            tun_addr: b.tun_addr,
            tun_addr_v6: b.tun_addr_v6,
            mtu: b.mtu,
            chains: b
                .chains
                .into_iter()
                .map(|c| StackChainEntry { name: c.name, socks5_addr: c.socks5_addr, group: c.group, nature: c.nature })
                .collect(),
            policy: build_policy(b.policy, &b.bypass),
            chain_dns: b
                .chain_dns
                .into_iter()
                .map(|d| ChainDnsConfig { chain_name: d.chain_name, servers: d.servers })
                .collect(),
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

// ── Privilege check ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn check_privileges() {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return;
    }
    if has_cap_net_admin() {
        tracing::warn!(
            "running as non-root with CAP_NET_ADMIN — per-process eBPF enforcement (cgroup \
             writes under /sys/fs/cgroup) and the eBPF loader itself may still need root or \
             CAP_BPF/CAP_SYS_ADMIN; those paths already degrade to a warning and stay disabled \
             if unavailable (see firewall.rs LinuxFirewall::activate)"
        );
        return;
    }
    tracing::error!(
        "refusing to start: mirage2tun needs root or CAP_NET_ADMIN to open /dev/net/tun, \
         install nft/iptables REDIRECT rules, and manage policy routing (ip rule / ip route). \
         Run as root, or grant the binary CAP_NET_ADMIN (setcap cap_net_admin+ep)."
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN_BIT: u64 = 12;
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            if let Ok(mask) = u64::from_str_radix(hex.trim(), 16) {
                return mask & (1u64 << CAP_NET_ADMIN_BIT) != 0;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn check_privileges() {
    tracing::warn!("not running on Linux — privilege check skipped; opening the TUN device will fail with a clear error");
}

// ── TCP forward loop (drives the real acceptor `LinuxTunStack::start` hands back) ──

async fn tcp_forward_loop(
    mut tcp: LinuxKernelTcpAcceptor,
    policy: Arc<PolicyEngine>,
    chains: Arc<ChainRegistry>,
    default_chain: String,
    metrics: Arc<StackMetrics>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accepted = tcp.accept() => {
                match accepted {
                    None => break,
                    Some((stream, orig_dst, peer)) => {
                        let policy = Arc::clone(&policy);
                        let chains = Arc::clone(&chains);
                        let metrics = Arc::clone(&metrics);
                        let default_chain = default_chain.clone();
                        tokio::spawn(handle_tcp_flow(stream, orig_dst, peer, policy, chains, default_chain, metrics));
                    }
                }
            }
        }
    }
    tracing::info!("TCP forward loop exiting");
}

async fn handle_tcp_flow(
    mut inbound: tokio::net::TcpStream,
    orig_dst: SocketAddr,
    peer: SocketAddr,
    policy: Arc<PolicyEngine>,
    chains: Arc<ChainRegistry>,
    default_chain: String,
    metrics: Arc<StackMetrics>,
) {
    let decision = policy.decide(orig_dst.ip(), orig_dst.port(), None, None).await;
    let is_bypass = matches!(&decision, PolicyDecision::Bypass);

    let dial_result: std::io::Result<(tokio::net::TcpStream, String)> = match decision {
        PolicyDecision::Bypass => dial_bypass(orig_dst).await.map(|s| (s, "bypass".to_owned())),
        PolicyDecision::Chain(name) => {
            let snap = chains.snapshot().await;
            let entry = snap.get(&name).or_else(|| snap.get(&default_chain));
            match entry {
                Some(e) => dial_socks5(e.socks5_addr, orig_dst).await.map(|s| (s, name)),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no chain '{name}' and no default chain configured"),
                )),
            }
        }
    };

    let mut outbound = match dial_result {
        Ok((s, via)) => {
            tracing::debug!(dst = %orig_dst, peer = %peer, via = %via, "forwarding");
            s
        }
        Err(e) => {
            tracing::warn!(dst = %orig_dst, peer = %peer, err = %e, "forward dial failed — dropping accepted stream");
            if is_bypass {
                metrics.bypass_fail.fetch_add(1, Ordering::Relaxed);
            } else {
                metrics.socks5_fail.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };

    metrics.active_tcp.fetch_add(1, Ordering::Relaxed);
    if is_bypass {
        metrics.bypass_ok.fetch_add(1, Ordering::Relaxed);
    } else {
        metrics.socks5_ok.fetch_add(1, Ordering::Relaxed);
    }

    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok((tx, rx)) => {
            metrics.bytes_tx.fetch_add(tx, Ordering::Relaxed);
            metrics.bytes_rx.fetch_add(rx, Ordering::Relaxed);
        }
        Err(e) => {
            tracing::warn!(dst = %orig_dst, err = %e, "forward copy ended with error");
        }
    }
    metrics.active_tcp.fetch_sub(1, Ordering::Relaxed);
}

/// Open an outbound TCP socket marked with `SO_MARK = BYPASS_FWMARK` so the
/// `ip rule` policy routing installed by `LinuxRouting::set_default_route`
/// sends it out the real NIC (main table) instead of back into the TUN
/// device's default route — without this mark, both the SOCKS5 dial-out and
/// any `Bypass` direct-dial would loop back into our own tunnel and go
/// nowhere (see `routing.rs`'s `BYPASS_FWMARK` and the `ip rule` pair it is
/// designed to be matched against).
async fn dial_marked(addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    #[cfg(target_os = "linux")]
    sock.set_mark(mirage_tun_linux::routing::BYPASS_FWMARK)?;
    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    tokio::net::TcpSocket::from_std_stream(std_stream).connect(addr).await
}

async fn dial_bypass(target: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    dial_marked(target).await
}

/// Open a SOCKS5 connection to `socks5_addr`, CONNECT to `target` (RFC 1928,
/// no-auth), and return the connected socket for the caller to pipe.
async fn dial_socks5(socks5_addr: SocketAddr, target: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let mut socks = dial_marked(socks5_addr).await?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    socks.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 auth method rejected: {resp:?}"),
        ));
    }

    let req = build_socks5_connect(target);
    socks.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    socks.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 CONNECT failed, reply code 0x{:02x}", hdr[1]),
        ));
    }
    let skip = match hdr[3] {
        0x01 => 4 + 2,  // IPv4 + port
        0x04 => 16 + 2, // IPv6 + port
        0x03 => {
            let mut len = [0u8; 1];
            socks.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        atyp => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("SOCKS5 unknown ATYP: 0x{atyp:02x}"),
            ))
        }
    };
    let mut tail = vec![0u8; skip];
    socks.read_exact(&mut tail).await?;

    Ok(socks)
}

fn build_socks5_connect(target: SocketAddr) -> Vec<u8> {
    let mut req = Vec::with_capacity(10);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV
    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    req
}

/// Drain the UDP path so the TUN-fd reader task inside `LinuxTunStack` never
/// stalls trying to hand off a datagram nobody reads — see the module doc
/// comment for why UDP-to-SOCKS5 forwarding itself is not implemented.
async fn drain_udp_unimplemented(mut udp: LinuxKernelUdpSocket, cancel: CancellationToken) {
    tracing::warn!(
        "UDP forwarding to a SOCKS5 chain is not implemented on Linux — intercepted UDP \
         datagrams (including UDP-based DNS through the tunnel) are read off the TUN device \
         and dropped; only TCP flows are forwarded"
    );
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            datagram = udp.recv() => {
                if datagram.is_none() {
                    break;
                }
                // Dropped — no SOCKS5 UDP relay on this platform yet.
            }
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

    rt.block_on(run(cli));
}

async fn run(cli: Cli) {
    check_privileges();

    let raw = std::fs::read_to_string(&cli.config).unwrap_or_else(|e| {
        tracing::error!(path = %cli.config, err = %e, "failed to read config");
        std::process::exit(1);
    });

    let bin_cfg: BinConfig = serde_json::from_str(&raw).unwrap_or_else(|e| {
        tracing::error!(err = %e, "failed to parse config");
        std::process::exit(1);
    });

    if bin_cfg.per_chain_tun {
        tracing::error!(
            "refusing to start: per_chain_tun=true was requested but mirage-tun-linux only \
             creates a single shared TUN device — starting anyway would silently give a weaker \
             isolation guarantee than the caller asked for"
        );
        std::process::exit(1);
    }
    if bin_cfg.tun_addr_v6.is_some() {
        tracing::warn!(
            "tun_addr_v6 is set but the Linux TUN device is configured IPv4-only on this \
             platform — IPv6 dual-stack is not implemented; the field is accepted for config \
             compatibility and otherwise ignored"
        );
    }
    if bin_cfg.chains.is_empty() {
        tracing::warn!(
            "no chains configured — every intercepted TCP connection will fail to route unless \
             the policy default_action is bypass"
        );
    }

    let api_bind_str = bin_cfg.api_bind.clone();
    let api_key = bin_cfg.api_key.clone();
    let cfg: StackConfig = bin_cfg.into();

    let chain_configs: Vec<ChainConfig> = cfg
        .chains
        .iter()
        .map(|c| ChainConfig {
            name: c.name.clone(),
            socks5_addr: c.socks5_addr.to_string(),
            protocol: ChainProtocol::Socks5,
            dns_upstream: None,
        })
        .collect();
    let default_chain_name = cfg.chains.first().map(|c| c.name.clone()).unwrap_or_else(|| "default".to_owned());
    let compiled_policy = CompiledPolicy::compile(cfg.policy.rules.clone(), cfg.policy.default_action.clone());

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

    match LinuxTunStack::start_with_cleanup(cfg, cancel.clone()).await {
        Ok((handle, cleanup)) => {
            let chains = Arc::new(ChainRegistry::new(chain_configs));
            let policy = Arc::new(PolicyEngine::new(compiled_policy));

            let api_bind: SocketAddr = api_bind_str.parse().unwrap_or_else(|e| {
                tracing::error!(val = %api_bind_str, err = %e, "invalid api_bind — using default");
                "127.0.0.1:19485".parse().expect("hardcoded fallback is valid")
            });
            tokio::spawn(api::serve(
                api_bind,
                Arc::clone(&handle.metrics),
                Arc::clone(&chains),
                Arc::clone(&policy),
                cancel.child_token(),
                api_key,
            ));

            tokio::spawn(drain_udp_unimplemented(handle.udp, cancel.child_token()));

            tcp_forward_loop(handle.tcp, policy, chains, default_chain_name, handle.metrics, cancel.clone()).await;

            // The forward loop only returns once `cancel` fired (or the
            // acceptor died — in which case make sure teardown still runs).
            // Either way, wait for `LinuxTunStack`'s own teardown task
            // (firewall deactivate, route restore, DNS revert, device close)
            // to actually finish before the process exits — see the doc
            // comment on `LinuxTunStack::start_with_cleanup`.
            cancel.cancel();
            if let Err(e) = cleanup.await {
                tracing::warn!(err = %e, "teardown task panicked");
            }
            tracing::info!("shutdown complete");
        }
        Err(e) => {
            tracing::error!(err = %e, "stack start failed");
            std::process::exit(1);
        }
    }
}
