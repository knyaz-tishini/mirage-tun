/// macOS TUN stack entry point.
///
/// `MacosTunStack::start()`:
///   1. Opens utun device.
///   2. Configures address via `ifconfig`.
///   3. Adds bypass host routes for relay addresses.
///   4. Sets up pf firewall (kill-switch + TCP rdr rule).
///   5. Sets up routing (0/1 + 128/1 trick).
///   6. Configures DNS.
///   7. Spawns TUN read loop that feeds packets into the UDP channel.
///   8. Spawns memory guard and route monitor.
///   9. Returns `StackHandle<MacosKernelTcpAcceptor, MacosKernelUdpSocket>`.
///
/// The macOS kernel handles TCP natively — no smoltcp required.
use crate::{
    dns::MacosDns,
    error::MacosTunError,
    firewall::MacosFirewall,
    kernel_tcp::MacosKernelTcpAcceptor,
    kernel_udp::MacosKernelUdpSocket,
    route_monitor::spawn_route_monitor,
    routing::MacosRouting,
    runtime_guard::{MemoryGuard, MemoryGuardConfig},
    tun_device::MacosTunDevice,
};
use async_trait::async_trait;
use mirage_tun_core::{
    metrics::StackMetrics,
    stack_config::StackConfig,
    traits::{PlatformDns, PlatformFirewall, PlatformRouting, TunDevice, TunStack, StackHandle, private::Sealed},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Default TCP intercept port. pf redirects TUN TCP traffic here.
const DEFAULT_INTERCEPT_PORT: u16 = 7891;

/// macOS TUN stack. Implements `TunStack` from mirage-tun-core.
pub struct MacosTunStack;

impl Sealed for MacosTunStack {}

#[async_trait]
impl TunStack for MacosTunStack {
    type Device = MacosTunDevice;
    type Tcp = MacosKernelTcpAcceptor;
    type Udp = MacosKernelUdpSocket;
    type Error = MacosTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        // 1. Open utun device (unit=0 → auto-assign)
        let mut device = MacosTunDevice::open(0)?;

        // 2. Configure address and MTU
        device.configure(&cfg.tun_addr, cfg.mtu).await?;

        let tun_name = device.interface_name().to_string();
        info!("utun interface: {} addr={} mtu={}", tun_name, cfg.tun_addr, cfg.mtu);

        // 3. Set up firewall (pf kill-switch + TCP rdr)
        let mut firewall = MacosFirewall::new();
        if cfg.kill_switch {
            firewall.activate(&cfg.relay_addrs, &tun_name, &[53])?;
        }

        // 4. Add bypass routes for relay addresses and set default route
        let routing = Arc::new(Mutex::new(MacosRouting::new()));
        {
            let mut r = routing.lock().await;
            for relay in &cfg.relay_addrs {
                r.add_bypass_host(*relay).await?;
            }
            r.set_default_route(&tun_name).await?;
        }

        // 5. Set DNS
        let mut dns = MacosDns::new();
        if !cfg.chain_dns.is_empty() {
            let servers: Vec<std::net::IpAddr> = cfg
                .chain_dns
                .iter()
                .flat_map(|c| c.servers.iter().copied())
                .collect();
            dns.set_dns(&tun_name, &servers).await?;
        }

        // 6. Bind TCP intercept listener
        let tcp_acceptor = MacosKernelTcpAcceptor::bind(DEFAULT_INTERCEPT_PORT).await?;

        // 7. Create UDP socket pair + spawn TUN read loop
        let (udp_socket, udp_tx, mut reply_rx) = MacosKernelUdpSocket::new();
        let metrics = Arc::new(StackMetrics::default());

        // Wrap device in Arc so the read and write loops can share it.
        let device = Arc::new(device);
        let device_writer = Arc::clone(&device);

        // TUN read loop: receives raw IP packets from utun, dispatches to UDP channel.
        // TCP packets are handled by the kernel — no further action needed for TCP.
        let read_metrics = Arc::clone(&metrics);
        let read_cancel = cancel.clone();
        let routing_teardown = Arc::clone(&routing);
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(1504);
            loop {
                tokio::select! {
                    _ = read_cancel.cancelled() => {
                        info!("TUN read loop cancelled");
                        break;
                    }
                    result = device.read_packet(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                let bytes_rx = &read_metrics.bytes_rx;
                                bytes_rx.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                                // Dispatch UDP (protocol=17) to the UDP channel.
                                // TCP (protocol=6) is handled natively by the kernel.
                                if buf.len() >= 10 && buf[9] == 17 {
                                    let _ = udp_tx.send(buf.clone()).await;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                error!("TUN read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            // Teardown on loop exit
            {
                let mut r = routing_teardown.lock().await;
                if let Err(e) = r.restore_routes().await {
                    error!("restore routes failed: {}", e);
                }
            }
            if let Err(e) = dns.revert_dns().await {
                error!("revert DNS failed: {}", e);
            }
            if let Err(e) = firewall.deactivate() {
                error!("firewall deactivate failed: {}", e);
            }
            // device is dropped here (last Arc ref) — OwnedFd closes the utun fd.
        });

        // Reply write loop: injects crafted UDP reply packets back into the utun fd.
        // `device_writer` is the second Arc clone — safe to use concurrently with the
        // read loop because `write_packet` takes `&self` (no exclusive borrow).
        let write_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = write_cancel.cancelled() => break,
                    pkt = reply_rx.recv() => {
                        match pkt {
                            None => break,
                            Some(p) => {
                                if let Err(e) = device_writer.write_packet(&p).await {
                                    error!("TUN write error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });

        // Memory guard — exits process on fatal RSS pressure so sentinel can respawn.
        let _memory_guard = MemoryGuard::spawn(MemoryGuardConfig::default(), Box::new(|| {
            tracing::error!("memory guard fatal — exiting");
            std::process::exit(1);
        }));

        // Route monitor — re-applies /1 routes if they drift (e.g. after sleep/wake).
        spawn_route_monitor(tun_name, Arc::clone(&routing), cancel.clone());

        Ok(StackHandle {
            tcp: tcp_acceptor,
            udp: udp_socket,
            metrics,
        })
    }
}
