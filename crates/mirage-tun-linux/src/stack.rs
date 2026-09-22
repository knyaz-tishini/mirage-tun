use std::collections::HashSet;
use std::sync::Arc;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::stack_config::StackConfig;
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::traits::{
    TunStack, TunDevice, StackHandle,
    PlatformFirewall, PlatformRouting, PlatformDns,
    private,
};

use crate::error::LinuxTunError;
use crate::tun_device::LinuxTunDevice;
use crate::kernel_tcp::LinuxKernelTcpAcceptor;
use crate::kernel_udp::{LinuxKernelUdpSocket, WriteSender};
use crate::firewall::{LinuxFirewall, DEFAULT_INTERCEPT_PORT};
use crate::routing::LinuxRouting;
use crate::dns::LinuxDns;

/// Entry point for the Linux TUN stack.
///
/// Usage:
/// ```ignore
/// let handle = LinuxTunStack::start(cfg, cancel).await?;
/// ```
///
/// `start()` (the `TunStack` trait method) spawns the teardown task and
/// discards its `JoinHandle` — fine for trait conformance, but it means a
/// caller has no way to know teardown (firewall deactivate, route restore,
/// DNS revert) actually finished before the process exits. A binary that
/// must guarantee clean shutdown on signal should call
/// [`LinuxTunStack::start_with_cleanup`] instead and await the returned
/// handle after cancelling.
///
/// `start_with_cleanup` also returns the `WriteSender` for the UDP lower
/// half (see `kernel_udp.rs`) alongside `StackHandle` — the trait's own
/// `StackHandle` has no room for it (it is shared, sealed shape across all
/// platforms), but a caller driving `handle.udp.recv()` in a loop needs it
/// to write per-flow replies back into the TUN fd without fighting that
/// loop for `&mut LinuxKernelUdpSocket` (see `crate::udp_socks5`).
pub struct LinuxTunStack;

impl private::Sealed for LinuxTunStack {}

impl LinuxTunStack {
    /// Same as the `TunStack::start` trait method, but also returns the
    /// `JoinHandle` of the spawned teardown task so the caller can await it
    /// after triggering `cancel` — the only way to guarantee firewall/routing/DNS
    /// cleanup has actually completed before the process exits — and the UDP
    /// `WriteSender` (see the doc comment on `LinuxTunStack` above).
    pub async fn start_with_cleanup(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<
        (StackHandle<LinuxKernelTcpAcceptor, LinuxKernelUdpSocket>, WriteSender, tokio::task::JoinHandle<()>),
        LinuxTunError,
    > {
        info!("LinuxTunStack::start — tun_name={} tun_addr={} mtu={}", cfg.tun_name, cfg.tun_addr, cfg.mtu);

        // ── 1. Open TUN device ────────────────────────────────────────────────
        let device_name = if cfg.tun_name.is_empty() { "tun0" } else { cfg.tun_name.as_str() };
        let mut device = LinuxTunDevice::open(device_name)?;
        let tun_name = device.name().to_owned();

        // ── 2. Configure address + MTU ────────────────────────────────────────
        device.configure(&cfg.tun_addr, cfg.mtu).await
            .map_err(|e| LinuxTunError::Other(e.to_string()))?;

        // ── 3. Routing ────────────────────────────────────────────────────────
        let mut routing = LinuxRouting::new();
        for &addr in &cfg.relay_addrs {
            routing.add_bypass_host(addr).await?;
        }
        routing.set_default_route(&tun_name).await?;

        // ── 4. Firewall (TCP REDIRECT) ────────────────────────────────────────
        // PlatformFirewall is a sync trait — call without .await.
        let mut firewall = LinuxFirewall::detect(DEFAULT_INTERCEPT_PORT);
        firewall.activate(&cfg.relay_addrs, &tun_name, &[])?;

        // ── 5. DNS ────────────────────────────────────────────────────────────
        let mut dns = LinuxDns::detect().await;
        if !cfg.chain_dns.is_empty() {
            let servers: Vec<std::net::IpAddr> = cfg
                .chain_dns
                .iter()
                .flat_map(|c| c.servers.iter().copied())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            dns.set_dns(&tun_name, &servers).await?;
        }

        // ── 6. TCP acceptor ───────────────────────────────────────────────────
        let tcp = LinuxKernelTcpAcceptor::bind(DEFAULT_INTERCEPT_PORT).await?;

        // ── 7. UDP socket (raw packet parsing from TUN fd) ────────────────────
        #[cfg(target_os = "linux")]
        let (udp, write_sender) = LinuxKernelUdpSocket::from_fd(device.raw_fd())?;

        #[cfg(not(target_os = "linux"))]
        let (udp, write_sender) = LinuxKernelUdpSocket::from_fd(0)?;

        // ── 8. Spawn cleanup task ─────────────────────────────────────────────
        // Handle returned to the caller so a binary can await it after
        // cancelling and be sure teardown actually finished (see doc comment
        // on `LinuxTunStack` above).
        let cleanup = tokio::spawn(async move {
            cancel.cancelled().await;
            info!("LinuxTunStack cancellation received — cleaning up");

            // PlatformFirewall::deactivate is sync.
            if let Err(e) = firewall.deactivate() {
                warn!("firewall deactivate: {e}");
            }
            if let Err(e) = routing.restore_routes().await {
                warn!("routing restore: {e}");
            }
            if let Err(e) = dns.revert_dns().await {
                warn!("dns revert: {e}");
            }
            // Device closes on drop.
            drop(device);
        });

        let metrics = Arc::new(StackMetrics::default());

        Ok((StackHandle { tcp, udp, metrics }, write_sender, cleanup))
    }
}

#[async_trait]
impl TunStack for LinuxTunStack {
    type Device = LinuxTunDevice;
    type Tcp = LinuxKernelTcpAcceptor;
    type Udp = LinuxKernelUdpSocket;
    type Error = LinuxTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        let (handle, _write_sender, _cleanup) = Self::start_with_cleanup(cfg, cancel).await?;
        Ok(handle)
    }
}
