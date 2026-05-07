/// macOS TUN stack — userspace TCP via mirage-tcpip-stack (smoltcp).
///
/// Architecture:
///   utun fd → read loop → smoltcp Stack (Sink) → TcpListener / UdpSocket
///   TcpListener → per-conn forward task → SOCKS5 → chain exit
///   UdpSocket → udp_forward loop → SOCKS5 UDP ASSOCIATE → chain exit
///   smoltcp Stack (Stream) → write loop → utun fd
use crate::{
    dns::MacosDns,
    dns_route::dns_via_socks5,
    error::MacosTunError,
    firewall::MacosFirewall,
    route_monitor::spawn_route_monitor,
    routing::MacosRouting,
    runtime_guard::{MemoryGuard, MemoryGuardConfig},
    smoltcp_acceptor::{SmoltcpTcpAcceptor, SmoltcpUdpSocket},
    tun_device::{MacosTunDevice, configure_interface_with_v6},
    udp_forward::{UdpProxySessionMap, udp_proxy_forward},
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{udp::UdpMsg, StackBuilder};
use mirage_tun_core::{
    metrics::StackMetrics,
    stack_config::StackConfig,
    traits::{
        private::Sealed, PlatformDns, PlatformFirewall, PlatformRouting, StackHandle, TunDevice,
        TunStack,
    },
};
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// macOS TUN stack. Implements `TunStack` from mirage-tun-core.
pub struct MacosTunStack;

impl Sealed for MacosTunStack {}

#[async_trait]
impl TunStack for MacosTunStack {
    type Device = MacosTunDevice;
    type Tcp = SmoltcpTcpAcceptor;
    type Udp = SmoltcpUdpSocket;
    type Error = MacosTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        if cfg.chains.len() > 1 {
            warn!(
                "MacosTunStack: {} chains configured — only first chain used for TCP forwarding",
                cfg.chains.len()
            );
        }

        let socks5_addr = cfg
            .chains
            .first()
            .map(|c| c.socks5_addr)
            .ok_or_else(|| MacosTunError::Other("no chains configured".to_string()))?;

        // Build per-chain DNS upstream map: chain_name → first server IP as SocketAddr :53.
        // Falls back to cfg.dns_upstream when chain has no entry.
        let chain_dns_map: HashMap<String, SocketAddr> = cfg
            .chain_dns
            .iter()
            .filter_map(|c| {
                c.servers.first().map(|ip| {
                    let sa = match ip {
                        IpAddr::V4(v4) => SocketAddr::from((*v4, 53)),
                        IpAddr::V6(v6) => SocketAddr::from((*v6, 53)),
                    };
                    (c.chain_name.clone(), sa)
                })
            })
            .collect();
        let global_dns_upstream = cfg.dns_upstream;
        // For the single-chain macOS stack, pick the first chain's DNS upstream.
        let dns_upstream_for_chain: SocketAddr = cfg
            .chains
            .first()
            .and_then(|c| chain_dns_map.get(&c.name).copied())
            .unwrap_or(global_dns_upstream);

        // 1. Open utun device
        let device = MacosTunDevice::open(0)?;
        let tun_name = device.interface_name().to_string();

        // 2. Configure IPv4 (and optional IPv6) on the same interface in one
        //    ifconfig pass — calling configure() then configure_interface_with_v6()
        //    runs ifconfig twice on the v4 args and clobbers the P2P peer.
        configure_interface_with_v6(
            &tun_name,
            &cfg.tun_addr,
            cfg.tun_addr_v6.as_deref(),
            cfg.mtu,
        )
        .await?;
        info!(
            "utun interface: {} addr={} v6={:?} mtu={}",
            tun_name, cfg.tun_addr, cfg.tun_addr_v6, cfg.mtu
        );

        // 3. Set up firewall (kill-switch only — no rdr)
        let mut firewall = MacosFirewall::new();
        if cfg.kill_switch {
            firewall.activate(&cfg.relay_addrs, &tun_name, &[53])?;
        }

        // 4. Add bypass routes for relay addresses
        let routing = Arc::new(Mutex::new(MacosRouting::new()));
        {
            let mut r = routing.lock().await;
            let local_addr = cfg.tun_addr.split('/').next().unwrap_or(&cfg.tun_addr);
            let peer_addr = derive_peer_ip(local_addr);
            if let Ok(p) = peer_addr.parse::<std::net::IpAddr>() {
                r.set_tun_peer(p);
            }
            // Set the v6 "peer" — for utun on macOS the TUN addr itself is used
            // as the nexthop for the ::/1 + 8000::/1 half-default routes.
            if let Some(ref v6_cidr) = cfg.tun_addr_v6 {
                let v6_addr_str = v6_cidr.split('/').next().unwrap_or(v6_cidr);
                if let Ok(v6_addr) = v6_addr_str.parse::<std::net::IpAddr>() {
                    r.set_tun_peer_v6(v6_addr);
                }
            }
            for relay in &cfg.relay_addrs {
                r.add_bypass_host(*relay).await?;
            }
            // 5. Set default route AFTER stack read loop is about to start
            r.set_default_route(&tun_name).await?;
        }

        // 6. Set DNS
        let mut dns = MacosDns::new();
        if !cfg.chain_dns.is_empty() {
            let servers: Vec<std::net::IpAddr> = cfg
                .chain_dns
                .iter()
                .flat_map(|c| c.servers.iter().copied())
                .collect();
            dns.set_dns(&tun_name, &servers).await?;
        }

        // 7. Build smoltcp stack
        let relay_set: Arc<std::collections::HashSet<std::net::IpAddr>> =
            Arc::new(cfg.relay_addrs.iter().copied().collect());
        let relay_set2 = relay_set.clone();

        let (stack, runner, udp_socket_opt, tcp_listener_opt) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(cfg.mtu as usize)
            .add_ip_filter_fn(move |_src, dst| !relay_set2.contains(dst))
            .build()
            .map_err(|e| MacosTunError::Other(format!("smoltcp build: {e}")))?;

        let tcp_listener = tcp_listener_opt
            .ok_or_else(|| MacosTunError::Other("TCP listener not returned".to_string()))?;
        let udp_socket = udp_socket_opt
            .ok_or_else(|| MacosTunError::Other("UDP socket not returned".to_string()))?;

        if let Some(r) = runner {
            tokio::spawn(r);
        }

        let (mut stack_sink, mut stack_stream) = stack.split();

        let metrics = Arc::new(StackMetrics::default());
        let device = Arc::new(device);
        let device_writer = Arc::clone(&device);

        // 8. Read loop: utun fd → smoltcp stack
        let read_cancel = cancel.clone();
        let routing_teardown = Arc::clone(&routing);
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(1504);
            loop {
                tokio::select! {
                    biased;
                    _ = read_cancel.cancelled() => {
                        info!("TUN read loop cancelled");
                        break;
                    }
                    result = device.read_packet(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                let pkt = buf.clone();
                                if let Err(e) = stack_sink.feed(pkt).await {
                                    warn!("stack sink error: {e}");
                                }
                                let _ = stack_sink.flush().await;
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
        });

        // 9. Write loop: smoltcp stack → utun fd
        let write_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = write_cancel.cancelled() => break,
                    pkt = stack_stream.next() => match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = device_writer.write_packet(&pkt).await {
                                error!("TUN write error: {}", e);
                            }
                        }
                        _ => break,
                    }
                }
            }
        });

        // 10. TCP accept loop: smoltcp TcpListener → SOCKS5 forward
        let tcp_cancel = cancel.clone();
        tokio::spawn(async move {
            tcp_accept_loop(tcp_listener, socks5_addr, tcp_cancel).await;
        });

        // 11. UDP forward loop: smoltcp UdpSocket → SOCKS5 UDP ASSOCIATE → chain
        let (udp_read, mut udp_write) = udp_socket.split();
        let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<UdpMsg>();

        // Writer half: inject SOCKS5 replies back into the smoltcp stack
        tokio::spawn(async move {
            while let Some(msg) = resp_rx.recv().await {
                if let Err(e) = udp_write.send(msg).await {
                    warn!("UDP forward: write into stack failed: {e}");
                    break;
                }
            }
        });

        // Reader half: receive from smoltcp, dispatch per-flow SOCKS5 sessions.
        // Port 53 → DNS-via-SOCKS5 TCP CONNECT (intercept before UDP ASSOCIATE).
        // All other UDP → SOCKS5 UDP ASSOCIATE.
        let udp_sessions: UdpProxySessionMap = Arc::new(Mutex::new(HashMap::new()));
        let udp_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut udp_read = udp_read;
            loop {
                tokio::select! {
                    biased;
                    _ = udp_cancel.cancelled() => break,
                    item = futures::StreamExt::next(&mut udp_read) => match item {
                        None => break,
                        Some((payload, src_addr, dst_addr)) => {
                            if dst_addr.port() == 53 {
                                // DNS intercept: TCP CONNECT through chain SOCKS5
                                // to the configured per-chain (or global) upstream.
                                // dst_addr.ip() from the guest is ignored — we always
                                // query dns_upstream_for_chain, matching Windows semantics
                                // where chain DNS overrides whatever the app asked.
                                let tx = resp_tx.clone();
                                let q = payload.clone();
                                let socks5 = socks5_addr;
                                let upstream = dns_upstream_for_chain;
                                tokio::spawn(async move {
                                    match dns_via_socks5(&q, socks5, upstream).await {
                                        Ok(response) => {
                                            // src/dst swap: reply from resolver back to guest.
                                            let _ = tx.send((response, dst_addr, src_addr));
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "DNS via SOCKS5 {upstream} failed: {e}"
                                            );
                                        }
                                    }
                                });
                            } else {
                                udp_proxy_forward(
                                    payload,
                                    src_addr,
                                    dst_addr,
                                    resp_tx.clone(),
                                    udp_sessions.clone(),
                                    socks5_addr,
                                ).await;
                            }
                        }
                    }
                }
            }
        });

        // 12. Memory guard + route monitor
        let _memory_guard = MemoryGuard::spawn(
            MemoryGuardConfig::default(),
            Box::new(|| {
                tracing::error!("memory guard fatal — exiting");
                std::process::exit(1);
            }),
        );

        spawn_route_monitor(tun_name, Arc::clone(&routing), cancel.clone());

        // UDP socket consumed by forward loop above; expose noop for StackHandle.
        let udp = SmoltcpUdpSocket::noop();

        // TCP forwarding is self-contained in tcp_accept_loop; expose noop for StackHandle.
        let tcp = SmoltcpTcpAcceptor::noop();

        Ok(StackHandle { tcp, udp, metrics })
    }
}

// ── SOCKS5 TCP forward ────────────────────────────────────────────────────────

async fn tcp_accept_loop(
    mut listener: mirage_tcpip_stack::TcpListener,
    socks5_addr: SocketAddr,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            conn = listener.next() => match conn {
                None => break,
                Some((stream, _local, remote)) => {
                    tokio::spawn(forward_tcp(stream, remote, socks5_addr));
                }
            }
        }
    }
}

/// Open a SOCKS5 connection to `socks5_addr`, CONNECT to `target`, then
/// bidirectionally pipe `stream` to the SOCKS5 channel.
///
/// SOCKS5 no-auth CONNECT per RFC 1928.
async fn forward_tcp(
    mut stream: mirage_tcpip_stack::TcpStream,
    target: SocketAddr,
    socks5_addr: SocketAddr,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut socks = match tokio::net::TcpStream::connect(socks5_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("SOCKS5 connect to {} failed: {}", socks5_addr, e);
            return;
        }
    };

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    if let Err(e) = socks.write_all(&[0x05, 0x01, 0x00]).await {
        warn!("SOCKS5 greeting write failed: {e}");
        return;
    }

    let mut resp = [0u8; 2];
    if let Err(e) = socks.read_exact(&mut resp).await {
        warn!("SOCKS5 greeting read failed: {e}");
        return;
    }
    if resp[0] != 0x05 || resp[1] != 0x00 {
        warn!("SOCKS5 auth method rejected: {:?}", resp);
        return;
    }

    // CONNECT request
    let req = build_socks5_connect(target);
    if let Err(e) = socks.write_all(&req).await {
        warn!("SOCKS5 CONNECT write failed: {e}");
        return;
    }

    // Response: VER RSP RSV ATYP ... (min 10 bytes for IPv4)
    let mut hdr = [0u8; 4];
    if let Err(e) = socks.read_exact(&mut hdr).await {
        warn!("SOCKS5 CONNECT response read failed: {e}");
        return;
    }
    if hdr[1] != 0x00 {
        warn!("SOCKS5 CONNECT failed, reply code: 0x{:02x}", hdr[1]);
        return;
    }
    // Drain bound address from response
    let skip = match hdr[3] {
        0x01 => 4 + 2,          // IPv4 + port
        0x04 => 16 + 2,         // IPv6 + port
        0x03 => {
            let mut len = [0u8; 1];
            if socks.read_exact(&mut len).await.is_err() {
                return;
            }
            len[0] as usize + 2
        }
        _ => {
            warn!("SOCKS5 unknown atyp: 0x{:02x}", hdr[3]);
            return;
        }
    };
    let mut tail = vec![0u8; skip];
    if let Err(e) = socks.read_exact(&mut tail).await {
        warn!("SOCKS5 bound addr read failed: {e}");
        return;
    }

    match tokio::io::copy_bidirectional(&mut stream, &mut socks).await {
        Ok(_) => {}
        Err(e) => warn!("TCP forward {target} error: {e}"),
    }
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

fn derive_peer_ip(local: &str) -> String {
    let parts: Vec<&str> = local.split('.').collect();
    if parts.len() == 4 {
        if let Ok(last) = parts[3].parse::<u8>() {
            let peer_last = if last == 1 { 2 } else { 1 };
            return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], peer_last);
        }
    }
    local.to_string()
}
