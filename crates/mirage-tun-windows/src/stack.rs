use std::{collections::HashSet, net::IpAddr, sync::Arc};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::StackBuilder;
use mirage_tun_core::{
    metrics::StackMetrics,
    stack_config::StackConfig,
    traits::{StackHandle, TunDevice, TunStack, private},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    tcp_acceptor::WintunTcpAcceptor,
    udp_socket::WintunUdpSocket,
    wintun::{WintunDevice, WintunHandle},
};

// ── Error conversion ──────────────────────────────────────────────────────────

/// Convert Windows-specific TunError to the core TunError.
fn win_err(e: crate::error::TunError) -> mirage_tun_core::error::TunError {
    mirage_tun_core::error::TunError::Other(e.to_string())
}

// ── WindowsTunStack ───────────────────────────────────────────────────────────

/// Windows implementation of the platform-agnostic TunStack trait.
///
/// Uses Wintun for the L3 TUN device and mirage-tcpip-stack (smoltcp) for TCP/UDP
/// demultiplexing. Returns raw TcpAcceptor + UdpSocket handles to the caller.
///
/// Note: the existing `IpStackRunner` + API service path is NOT affected by this
/// type — it continues to work as before. `WindowsTunStack` is a separate entry
/// point intended for consumers of the core TunStack trait.
pub struct WindowsTunStack;

impl private::Sealed for WindowsTunStack {}

#[async_trait]
impl TunStack for WindowsTunStack {
    type Device = NoopTunDevice;
    type Tcp = WintunTcpAcceptor;
    type Udp = WintunUdpSocket;
    type Error = mirage_tun_core::error::TunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<WintunTcpAcceptor, WintunUdpSocket>, mirage_tun_core::error::TunError> {
        // ── Step 1: Create and configure Wintun adapter ──────────────────────
        // D9: use cfg.tun_name instead of hardcoded "mirage0" (bug 20 fix).
        let handle = WintunHandle::create(
            &cfg.tun_name,
            &cfg.tun_addr,
            cfg.tun_addr_v6.as_deref(),
            cfg.mtu,
            None, // tunnel_type: None = default "Mirage"; set via TunConfig on the main service path
        )
        .await
        .map_err(win_err)?;
        let device = WintunDevice::new(&handle);
        let (wintun_rx, wintun_tx) = device.take_channels();

        // ── Step 2: Build smoltcp stack ───────────────────────────────────────
        // Filter: relay addrs must never enter the stack (would create routing loops).
        let relay_set: Arc<HashSet<IpAddr>> =
            Arc::new(cfg.relay_addrs.into_iter().collect());
        let relay_set2 = relay_set.clone();

        let (stack, runner, udp_socket_opt, tcp_listener_opt) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(1500)
            .add_ip_filter_fn(move |_src, dst| !relay_set2.contains(dst))
            .build()
            .map_err(|e| mirage_tun_core::error::TunError::SmoltcpBuild(e.to_string()))?;

        let tcp_listener = tcp_listener_opt.ok_or_else(|| {
            mirage_tun_core::error::TunError::Other(
                "StackBuilder: TCP listener not returned".to_owned(),
            )
        })?;
        let udp_socket = udp_socket_opt.ok_or_else(|| {
            mirage_tun_core::error::TunError::Other(
                "StackBuilder: UDP socket not returned".to_owned(),
            )
        })?;

        // ── Step 3: Spawn the smoltcp runner ──────────────────────────────────
        if let Some(r) = runner {
            tokio::spawn(r);
        }

        // ── Step 4: Split stack and start I/O pumps ───────────────────────────
        let (stack_sink, stack_stream) = stack.split();

        tokio::spawn(pump_wintun_to_stack(wintun_rx, stack_sink, cancel.clone()));
        tokio::spawn(pump_stack_to_wintun(stack_stream, wintun_tx, cancel));

        // ── Step 5: Wrap TCP/UDP in platform-agnostic types ───────────────────
        let tcp_acceptor = WintunTcpAcceptor::new(tcp_listener);
        let udp = WintunUdpSocket::new(udp_socket);
        let metrics = Arc::new(StackMetrics::default());

        info!(
            tun_addr = %cfg.tun_addr,
            mtu = cfg.mtu,
            "WindowsTunStack: started"
        );

        Ok(StackHandle { tcp: tcp_acceptor, udp, metrics })
    }
}

// ── Wintun ↔ Stack pumps ──────────────────────────────────────────────────────

async fn pump_wintun_to_stack(
    mut wintun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut stack_sink: futures::stream::SplitSink<
        mirage_tcpip_stack::Stack,
        mirage_tcpip_stack::AnyIpPktFrame,
    >,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = wintun_rx.recv() => match pkt {
                None => break,
                Some(pkt) => {
                    if let Err(e) = stack_sink.feed(pkt).await {
                        warn!("pump wintun→stack: sink error: {e}");
                        continue;
                    }
                    while let Ok(pkt) = wintun_rx.try_recv() {
                        if let Err(e) = stack_sink.feed(pkt).await {
                            warn!("pump wintun→stack: sink error: {e}");
                            break;
                        }
                    }
                    let _ = stack_sink.flush().await;
                }
            }
        }
    }
}

async fn pump_stack_to_wintun(
    mut stack_stream: futures::stream::SplitStream<mirage_tcpip_stack::Stack>,
    wintun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = stack_stream.next() => match pkt {
                Some(Ok(pkt)) => {
                    if wintun_tx.send(pkt).await.is_err() {
                        warn!("pump stack→wintun: channel closed");
                        break;
                    }
                }
                _ => break,
            }
        }
    }
}

// ── NoopTunDevice ─────────────────────────────────────────────────────────────
//
// TunStack::Device is a required associated type but WindowsTunStack does not
// expose a TunDevice to the consumer — the Wintun device is managed internally.
// This placeholder satisfies the type constraint and carries the configured name.

pub struct NoopTunDevice {
    // D9: carry the adapter name from StackConfig so Name() reflects config.
    name: String,
}

impl private::Sealed for NoopTunDevice {}

#[async_trait]
impl TunDevice for NoopTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn configure(
        &mut self,
        _addr: &str,
        _mtu: u16,
    ) -> Result<(), mirage_tun_core::error::TunError> {
        Ok(())
    }

    async fn close(self) -> Result<(), mirage_tun_core::error::TunError> {
        Ok(())
    }
}
