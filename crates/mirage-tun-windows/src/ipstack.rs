use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    time::Instant,
};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{
    udp::UdpMsg, AnyIpPktFrame, StackBuilder, TcpListener, UdpSocket,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, Mutex, Semaphore},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::chains::{ChainMap, ChainRegistry};
use crate::dns_map::DnsMap;
use crate::error::{Result, TunError};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::process_info::ProcessResolver;
use crate::wintun::WintunDevice;

pub struct IpStackRunner;

impl IpStackRunner {
    pub async fn start(
        device: WintunDevice,
        chain_registry: Arc<ChainRegistry>,
        cancel: CancellationToken,
        relay_addrs: Vec<IpAddr>,
        if_index: u32,
        policy: Arc<PolicyEngine>,
        dns_map: Arc<DnsMap>,
        native_dns: Option<SocketAddr>,
        process_resolver: Arc<ProcessResolver>,
    ) -> Result<Self> {
        // Snapshot for logging only — not used in the hot path.
        let snap = chain_registry.snapshot().await;
        let default_socks5 = snap.get("default").copied()
            .or_else(|| snap.values().next().copied());

        info!(
            "IpStackRunner: started, default_socks5={default_socks5:?}, chains={}, \
             relay_bypass={relay_addrs:?}, if_index={if_index}",
            snap.len(),
        );

        let relay_set: Arc<HashSet<IpAddr>> =
            Arc::new(relay_addrs.into_iter().collect());
        let relay_set2 = relay_set.clone();

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(1500)
            .add_ip_filter_fn(move |_src, dst| !relay_set2.contains(dst))
            .build()
            .map_err(TunError::SmoltcpBuild)?;

        let tcp_listener = tcp_listener.expect("tcp enabled in StackBuilder");
        let udp_socket = udp_socket.expect("udp enabled in StackBuilder");

        if let Some(r) = runner {
            tokio::spawn(r);
        }

        let (stack_sink, stack_stream) = stack.split();
        let (wintun_rx, wintun_tx) = device.take_channels();

        let socks5_semaphore = Arc::new(Semaphore::new(100));

        let stats = Arc::new(PumpStats::default());

        tokio::spawn(pump_wintun_to_stack(
            wintun_rx,
            stack_sink,
            cancel.clone(),
            stats.clone(),
        ));
        tokio::spawn(pump_stack_to_wintun(
            stack_stream,
            wintun_tx,
            cancel.clone(),
            stats.clone(),
        ));
        tokio::spawn(tcp_accept_loop(
            tcp_listener,
            chain_registry.clone(),
            socks5_semaphore,
            if_index,
            cancel.clone(),
            stats.clone(),
            policy.clone(),
            dns_map.clone(),
            process_resolver,
        ));
        tokio::spawn(udp_dns_loop(
            udp_socket,
            chain_registry,
            if_index,
            cancel.clone(),
            policy,
            dns_map,
            native_dns,
        ));

        // Stats printer
        let stats2 = stats.clone();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel2.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                        let s = &stats2;
                        info!(
                            "TUN stats: wintun→stack={} stack→wintun={} tcp_accept={} socks5_ok={} socks5_fail={} bypass_ok={} bypass_fail={} sink_err={}",
                            s.wintun_to_stack.load(Ordering::Relaxed),
                            s.stack_to_wintun.load(Ordering::Relaxed),
                            s.tcp_accepted.load(Ordering::Relaxed),
                            s.socks5_ok.load(Ordering::Relaxed),
                            s.socks5_fail.load(Ordering::Relaxed),
                            s.bypass_ok.load(Ordering::Relaxed),
                            s.bypass_fail.load(Ordering::Relaxed),
                            s.sink_errors.load(Ordering::Relaxed),
                        );
                    }
                }
            }
        });

        Ok(Self)
    }
}

// ── Stats ────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct PumpStats {
    wintun_to_stack: AtomicU64,
    stack_to_wintun: AtomicU64,
    tcp_accepted: AtomicU64,
    socks5_ok: AtomicU64,
    socks5_fail: AtomicU64,
    sink_errors: AtomicU64,
    bypass_ok: AtomicU64,
    bypass_fail: AtomicU64,
}

// ── Wintun ↔ Stack pumps ──────────────────────────────────────────────────────

async fn pump_wintun_to_stack(
    mut wintun_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut stack_sink: futures::stream::SplitSink<netstack_smoltcp::Stack, AnyIpPktFrame>,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
) {
    use futures::SinkExt;
    info!("pump_wintun_to_stack: pump started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = wintun_rx.recv() => match pkt {
                None => break,
                Some(pkt) => {
                    stats.wintun_to_stack.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = stack_sink.feed(pkt).await {
                        stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                        warn!("pump wintun→stack: sink error: {e}");
                        continue;
                    }
                    // Drain any additional packets already in the channel before flushing.
                    while let Ok(pkt) = wintun_rx.try_recv() {
                        stats.wintun_to_stack.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = stack_sink.feed(pkt).await {
                            stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                            warn!("pump wintun→stack: sink error: {e}");
                            break;
                        }
                    }
                    // Single flush for the whole batch.
                    let _ = stack_sink.flush().await;
                }
            }
        }
    }
}

async fn pump_stack_to_wintun(
    mut stack_stream: futures::stream::SplitStream<netstack_smoltcp::Stack>,
    wintun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
) {
    info!("pump_stack_to_wintun: pump started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = stack_stream.next() => match pkt {
                Some(Ok(pkt)) => {
                    stats.stack_to_wintun.fetch_add(1, Ordering::Relaxed);
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

// ── TCP accept loop ───────────────────────────────────────────────────────────

async fn tcp_accept_loop(
    mut tcp_listener: TcpListener,
    chain_registry: Arc<ChainRegistry>,
    socks5_semaphore: Arc<Semaphore>,
    if_index: u32,
    cancel: CancellationToken,
    stats: Arc<PumpStats>,
    policy: Arc<PolicyEngine>,
    dns_map: Arc<DnsMap>,
    process_resolver: Arc<ProcessResolver>,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                info!("IpStackRunner: cancelled, exiting TCP accept loop");
                break;
            }
            item = tcp_listener.next() => match item {
                None => break,
                Some((stream, local_addr, remote_addr)) => {
                    let dst = remote_addr;
                    let src_port = local_addr.port();
                    stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);

                    // App-based process lookup (spawn_blocking — sync Win32 calls)
                    let resolver = process_resolver.clone();
                    let app_info = tokio::task::spawn_blocking(move || {
                        resolver.resolve(src_port, dst)
                    })
                    .await
                    .ok()
                    .flatten();

                    // Policy decision
                    let domain_hint = dns_map.get(&dst.ip());
                    let decision = policy
                        .decide(dst.ip(), dst.port(), domain_hint.as_deref(), app_info.as_ref())
                        .await;

                    let exe_short = app_info.as_ref().map(|i| {
                        i.exe_path.rsplit_once('\\')
                            .map(|(_, name)| name)
                            .unwrap_or(&i.exe_path)
                            .to_owned()
                    });

                    let cancel2 = cancel.clone();
                    let stats2 = stats.clone();

                    match decision {
                        PolicyDecision::Bypass => {
                            info!("TCP {dst}: BYPASS app={} domain={domain_hint:?}",
                                exe_short.as_deref().unwrap_or("?"));
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = cancel2.cancelled() => {}
                                    r = handle_bypass_tcp(stream, dst, if_index) => {
                                        match r {
                                            Ok(_) => { stats2.bypass_ok.fetch_add(1, Ordering::Relaxed); }
                                            Err(e) => {
                                                stats2.bypass_fail.fetch_add(1, Ordering::Relaxed);
                                                warn!("IpStackRunner: TCP {dst} bypass error: {e}");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        PolicyDecision::Chain(chain_name) => {
                            // Snapshot the live registry at connection time — always current.
                            let chain_snap: Arc<ChainMap> = chain_registry.snapshot().await;
                            let socks5_addr = match chain_snap.get(&chain_name).copied() {
                                Some(addr) => addr,
                                None => {
                                    warn!("TCP {dst}: chain '{chain_name}' not found in registry — dropping");
                                    continue;
                                }
                            };
                            let sem = socks5_semaphore.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = cancel2.cancelled() => {}
                                    r = handle_tcp(stream, socks5_addr, dst, sem, if_index) => {
                                        match &r {
                                            Ok(_) => { stats2.socks5_ok.fetch_add(1, Ordering::Relaxed); }
                                            Err(e) => {
                                                stats2.socks5_fail.fetch_add(1, Ordering::Relaxed);
                                                warn!("IpStackRunner: TCP {dst} chain '{chain_name}' error: {e}");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }
    }
}

// ── UDP / DNS loop ────────────────────────────────────────────────────────────

const DNS_UPSTREAM: SocketAddr = SocketAddr::new(
    IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
    53,
);
const DNS_CONCURRENCY: usize = 8;
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const DNS_CACHE_MAX: usize = 1024;

struct DnsCache {
    entries: HashMap<Vec<u8>, (Vec<u8>, Instant)>,
}

impl DnsCache {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    fn get(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let key = Self::cache_key(query);
        if let Some((resp, ts)) = self.entries.get(&key) {
            if ts.elapsed() < DNS_CACHE_TTL {
                let mut cached = resp.clone();
                // Patch transaction ID in response to match query
                if query.len() >= 2 && cached.len() >= 2 {
                    cached[0] = query[0];
                    cached[1] = query[1];
                }
                return Some(cached);
            }
            self.entries.remove(&key);
        }
        None
    }

    fn put(&mut self, query: &[u8], response: &[u8]) {
        if self.entries.len() >= DNS_CACHE_MAX {
            // Evict oldest
            let oldest = self.entries.iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        let key = Self::cache_key(query);
        self.entries.insert(key, (response.to_vec(), Instant::now()));
    }

    // Cache key = query minus transaction ID (first 2 bytes)
    fn cache_key(query: &[u8]) -> Vec<u8> {
        if query.len() > 2 { query[2..].to_vec() } else { query.to_vec() }
    }
}

// ── UDP bypass session map ───────────────────────────────────────────────────

/// Key: (client_src, original_dst) — one entry per active UDP bypass session.
type UdpSessionMap = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>>;

async fn udp_bypass_forward(
    payload: Vec<u8>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    resp_tx: mpsc::UnboundedSender<UdpMsg>,
    sessions: UdpSessionMap,
    if_index: u32,
) {
    // Check if session already exists.
    {
        let map = sessions.lock().await;
        if let Some(tx) = map.get(&(src_addr, dst_addr)) {
            let _ = tx.send(payload);
            return;
        }
    }

    // No session — create one.
    let (fwd_tx, mut fwd_rx) = mpsc::channel::<Vec<u8>>(64);

    {
        let mut map = sessions.lock().await;
        // Insert; send initial payload.
        map.insert((src_addr, dst_addr), fwd_tx.clone());
    }
    let _ = fwd_tx.send(payload).await;

    let sessions2 = sessions.clone();
    tokio::spawn(async move {
        const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        // Create a native UDP socket bound via IP_UNICAST_IF.
        let sock = match create_udp_bypass_socket(if_index) {
            Ok(s) => s,
            Err(e) => {
                warn!("UDP bypass: socket create failed for {dst_addr}: {e}");
                sessions2.lock().await.remove(&(src_addr, dst_addr));
                return;
            }
        };

        let mut recv_buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                // Forward inbound datagrams to dst.
                msg = tokio::time::timeout(UDP_IDLE_TIMEOUT, fwd_rx.recv()) => {
                    match msg {
                        Ok(Some(data)) => {
                            if let Err(e) = sock.send_to(&data, dst_addr).await {
                                warn!("UDP bypass: send to {dst_addr} failed: {e}");
                                break;
                            }
                        }
                        Ok(None) | Err(_) => {
                            // Channel closed or idle timeout.
                            break;
                        }
                    }
                }
                // Receive responses and push back into TUN.
                result = tokio::time::timeout(UDP_IDLE_TIMEOUT, sock.recv_from(&mut recv_buf)) => {
                    match result {
                        Ok(Ok((n, _from))) => {
                            let response = recv_buf[..n].to_vec();
                            // src/dst are swapped: TUN sees response as coming from dst.
                            let _ = resp_tx.send((response, dst_addr, src_addr));
                        }
                        Ok(Err(e)) => {
                            warn!("UDP bypass: recv from {dst_addr} failed: {e}");
                            break;
                        }
                        Err(_) => {
                            // Idle timeout.
                            break;
                        }
                    }
                }
            }
        }

        sessions2.lock().await.remove(&(src_addr, dst_addr));
    });
}

/// Bind a socket to a specific interface via `IP_UNICAST_IF` / `IPV6_UNICAST_IF` setsockopt.
///
/// For IPv4, the index is passed in big-endian (network byte order) as required by
/// `IP_UNICAST_IF` on Windows. For IPv6, it is passed in native byte order as required by
/// `IPV6_UNICAST_IF`. No-op when `if_index == 0`.
#[cfg(windows)]
fn bind_to_interface(sock: &socket2::Socket, if_index: u32, is_ipv4: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    if if_index == 0 {
        return Ok(());
    }

    let (level, optname, index_val) = if is_ipv4 {
        (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
            31i32, // IP_UNICAST_IF
            u32::to_be(if_index),
        )
    } else {
        (
            windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
            31i32, // IPV6_UNICAST_IF
            if_index, // native byte order for IPv6
        )
    };

    unsafe {
        let ret = windows_sys::Win32::Networking::WinSock::setsockopt(
            sock.as_raw_socket() as usize,
            level,
            optname,
            &index_val as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        );
        if ret == windows_sys::Win32::Networking::WinSock::SOCKET_ERROR {
            return Err(std::io::Error::from_raw_os_error(
                windows_sys::Win32::Networking::WinSock::WSAGetLastError(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn create_udp_bypass_socket(if_index: u32) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().expect("static addr is valid");
    sock.bind(&bind_addr.into())?;
    bind_to_interface(&sock, if_index, true)?;
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_udp)
}

#[cfg(not(windows))]
fn create_udp_bypass_socket(_if_index: u32) -> std::io::Result<tokio::net::UdpSocket> {
    // Blocking bind, but only on non-Windows (test/dev builds).
    let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    std_sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_sock)
}

async fn udp_dns_loop(
    udp_socket: UdpSocket,
    chain_registry: Arc<ChainRegistry>,
    if_index: u32,
    cancel: CancellationToken,
    policy: Arc<PolicyEngine>,
    dns_map: Arc<DnsMap>,
    native_dns: Option<SocketAddr>,
) {
    let (mut read_half, write_half) = udp_socket.split();
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<UdpMsg>();

    let mut write_half = write_half;
    tokio::spawn(async move {
        while let Some(msg) = resp_rx.recv().await {
            if let Err(e) = write_half.send(msg).await {
                warn!("IpStackRunner: UDP DNS write error: {e}");
                break;
            }
        }
    });

    let dns_sem = Arc::new(Semaphore::new(DNS_CONCURRENCY));
    let cache = Arc::new(Mutex::new(DnsCache::new()));
    let udp_sessions: UdpSessionMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            item = read_half.next() => match item {
                None => break,
                Some((payload, src_addr, dst_addr)) => {
                    if dst_addr.port() != 53 {
                        let dst_ip = dst_addr.ip();
                        let domain_hint = dns_map.get(&dst_ip);
                        let decision = policy
                            .decide(dst_ip, dst_addr.port(), domain_hint.as_deref(), None)
                            .await;

                        if decision == PolicyDecision::Bypass {
                            udp_bypass_forward(
                                payload,
                                src_addr,
                                dst_addr,
                                resp_tx.clone(),
                                udp_sessions.clone(),
                                if_index,
                            )
                            .await;
                        } else {
                            warn!("UDP non-DNS {dst_addr}: Chain policy — dropped (SOCKS5 UDP not supported)");
                        }
                        continue;
                    }
                    // Check cache first (no upstream query needed)
                    {
                        let mut c = cache.lock().await;
                        if let Some(cached) = c.get(&payload) {
                            let _ = resp_tx.send((cached, dst_addr, src_addr));
                            continue;
                        }
                    }

                    // Extract domain and check policy BEFORE spawning (no locks held)
                    let domain = extract_dns_domain(&payload);
                    let decision = if let Some(ref dom) = domain {
                        policy.domain_decision(dom).await
                    } else {
                        PolicyDecision::default_chain()
                    };

                    let tx = resp_tx.clone();
                    let sem = dns_sem.clone();
                    let cache2 = cache.clone();
                    let dns_map2 = dns_map.clone();

                    if decision == PolicyDecision::Bypass {
                        if let Some(ndns) = native_dns {
                            tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return,
                                };
                                match dns_via_native(&payload, ndns, if_index).await {
                                    Ok(response) => {
                                        if let Some(ref dom) = domain {
                                            let ips = extract_dns_ips(&response);
                                            if !ips.is_empty() {
                                                dns_map2.insert_many(&ips, dom);
                                            }
                                        }
                                        {
                                            let mut c = cache2.lock().await;
                                            c.put(&payload, &response);
                                        }
                                        let _ = tx.send((response, dst_addr, src_addr));
                                    }
                                    Err(e) => {
                                        warn!("IpStackRunner: DNS via native failed: {e}");
                                    }
                                }
                            });
                            continue;
                        }
                        // native_dns not configured — fall through to SOCKS5 default
                    }

                    // SOCKS5 path — resolve chain from registry (live snapshot).
                    // For Bypass that fell through, and for Chain(name), use the
                    // named chain's SOCKS5; fall back to "default" if name is missing.
                    let chain_snap: Arc<ChainMap> = chain_registry.snapshot().await;
                    let socks5_addr = match &decision {
                        PolicyDecision::Chain(name) => {
                            // Try the named chain first, then fall back to "default".
                            chain_snap.get(name.as_str()).copied()
                                .or_else(|| chain_snap.get("default").copied())
                                .or_else(|| chain_snap.values().next().copied())
                        }
                        PolicyDecision::Bypass => {
                            // Fell through because native_dns was None.
                            chain_snap.get("default").copied()
                                .or_else(|| chain_snap.values().next().copied())
                        }
                    };

                    let socks5_addr = match socks5_addr {
                        Some(addr) => addr,
                        None => {
                            warn!("DNS query: no chain configured — dropping");
                            continue;
                        }
                    };

                    tokio::spawn(async move {
                        let _permit = match sem.acquire().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        match dns_via_socks5_inner(&payload, socks5_addr, if_index).await {
                            Ok(response) => {
                                if let Some(ref dom) = domain {
                                    let ips = extract_dns_ips(&response);
                                    if !ips.is_empty() {
                                        dns_map2.insert_many(&ips, dom);
                                    }
                                }
                                {
                                    let mut c = cache2.lock().await;
                                    c.put(&payload, &response);
                                }
                                let _ = tx.send((response, dst_addr, src_addr));
                            }
                            Err(e) => {
                                warn!("IpStackRunner: DNS via SOCKS5 failed: {e}");
                            }
                        }
                    });
                }
            }
        }
    }
}

// ── DNS parsing helpers ───────────────────────────────────────────────────────

fn extract_dns_domain(query: &[u8]) -> Option<String> {
    if query.len() < 13 {
        return None;
    }
    let mut pos = 12;
    let mut parts = Vec::new();
    loop {
        if pos >= query.len() {
            return None;
        }
        let len = query[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        parts.push(std::str::from_utf8(&query[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= data.len() {
            return data.len();
        }
        let b = data[pos];
        if b == 0 {
            return pos + 1;
        }
        if b & 0xC0 == 0xC0 {
            return pos + 2;
        }
        pos += 1 + b as usize;
    }
}

fn extract_dns_ips(response: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if response.len() < 12 {
        return ips;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(response, pos);
        pos += 4; // QTYPE + QCLASS
        if pos > response.len() {
            return ips;
        }
    }

    // Parse answer section
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }
        pos = skip_dns_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                let ip = std::net::Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                );
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    ips
}

// ── Native DNS (bypass path) ──────────────────────────────────────────────────

#[cfg(windows)]
async fn dns_via_native(
    query: &[u8],
    native_dns: SocketAddr,
    if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use socket2::{Domain, Protocol, Socket, Type};

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().expect("static addr is valid");
    sock.bind(&bind_addr.into())?;
    bind_to_interface(&sock, if_index, true)?;
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    let tokio_udp = tokio::net::UdpSocket::from_std(std_udp)?;
    tokio_udp.send_to(query, native_dns).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio_udp.recv(&mut buf),
    )
    .await??;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(not(windows))]
async fn dns_via_native(
    query: &[u8],
    native_dns: SocketAddr,
    _if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp.send_to(query, native_dns).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        udp.recv(&mut buf),
    )
    .await??;
    buf.truncate(n);
    Ok(buf)
}

pub(crate) async fn dns_via_socks5_inner(
    query: &[u8],
    socks5_addr: SocketAddr,
    if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err = None;
    for attempt in 0..2u8 {
        match dns_tcp_query(query, socks5_addr, if_index).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = Some(e);
                if attempt == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
    Err(last_err.unwrap())
}

async fn dns_tcp_query(
    query: &[u8],
    socks5_addr: SocketAddr,
    if_index: u32,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = socks5_connect(socks5_addr, DNS_UPSTREAM, if_index).await?;

    // DNS-over-TCP: 2-byte big-endian length prefix
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len > 65535 {
        return Err("DNS response too large".into());
    }

    let mut response = vec![0u8; resp_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

// ── TCP bypass (direct via native interface) ──────────────────────────────────

async fn handle_bypass_tcp(
    mut tcp: netstack_smoltcp::TcpStream,
    dst: SocketAddr,
    if_index: u32,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut native = connect_via_interface(dst, if_index).await?;
    tokio::io::copy_bidirectional_with_sizes(&mut tcp, &mut native, 64 * 1024, 64 * 1024).await?;
    Ok(())
}

// ── TCP → SOCKS5 ──────────────────────────────────────────────────────────────

async fn handle_tcp(
    mut tcp: netstack_smoltcp::TcpStream,
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    socks5_semaphore: Arc<Semaphore>,
    if_index: u32,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let t0 = Instant::now();
    let mut proxy =
        socks5_connect_with_semaphore(socks5_addr, dst, &socks5_semaphore, if_index).await?;
    let socks5_ms = t0.elapsed().as_millis();

    // Read first bytes from smoltcp to measure handshake + first data latency
    let t1 = Instant::now();
    let mut first_buf = [0u8; 8192];
    let first_n = tcp.read(&mut first_buf).await?;
    let first_read_ms = t1.elapsed().as_millis();

    // Write those first bytes to proxy
    if first_n > 0 {
        proxy.write_all(&first_buf[..first_n]).await?;
    }

    let t2 = Instant::now();
    let (a_to_b, b_to_a) = tokio::io::copy_bidirectional_with_sizes(&mut tcp, &mut proxy, 64 * 1024, 64 * 1024).await?;
    let relay_ms = t2.elapsed().as_millis();

    let total_ms = t0.elapsed().as_millis();
    if total_ms > 1000 {
        info!("TCP {dst}: socks5={socks5_ms}ms first_read={first_read_ms}ms({first_n}B) relay={relay_ms}ms tx={a_to_b} rx={b_to_a}");
    }
    Ok(())
}

// ── SOCKS5 connect with concurrency limit ────────────────────────────────────

async fn socks5_connect_with_semaphore(
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    semaphore: &Semaphore,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let _permit = semaphore
        .acquire()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut last_err = None;
    for attempt in 0..3u8 {
        match socks5_connect(socks5_addr, dst, if_index).await {
            Ok(proxy) => return Ok(proxy),
            Err(e) => {
                warn!("IpStackRunner: SOCKS5 to {dst} attempt {attempt} failed: {e}");
                last_err = Some(e);
                if attempt < 2 {
                    // Short backoff for localhost proxy: 50ms, 100ms
                    let delay = 50u64 * (1 << attempt);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

// ── Interface-bound TCP connect ───────────────────────────────────────────────

#[cfg(windows)]
async fn connect_via_interface(
    remote: SocketAddr,
    if_index: u32,
) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let is_ipv4 = remote.is_ipv4();
    let domain = if is_ipv4 { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_to_interface(&sock, if_index, is_ipv4)?;
    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    let tokio_sock = tokio::net::TcpSocket::from_std_stream(std_stream);
    tokio_sock.connect(remote).await
}

#[cfg(not(windows))]
async fn connect_via_interface(
    remote: SocketAddr,
    _if_index: u32,
) -> std::io::Result<TcpStream> {
    TcpStream::connect(remote).await
}

// ── SOCKS5 no-auth connect ────────────────────────────────────────────────────

async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let effective_if = if proxy.ip().is_loopback() { 0 } else { if_index };
    let mut stream = connect_via_interface(proxy, effective_if).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(format!(
            "SOCKS5 greeting rejected: {:02x} {:02x}",
            greeting_resp[0], greeting_resp[1]
        )
        .into());
    }

    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    stream.write_all(&req).await?;

    let mut resp_hdr = [0u8; 4];
    stream.read_exact(&mut resp_hdr).await?;

    if resp_hdr[0] != 0x05 {
        return Err(format!("SOCKS5 bad version in response: {}", resp_hdr[0]).into());
    }
    if resp_hdr[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected, code: {}", resp_hdr[1]).into());
    }

    match resp_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut skip = vec![0u8; len + 2];
            stream.read_exact(&mut skip).await?;
        }
        atyp => {
            return Err(format!("SOCKS5 unknown ATYP in response: {atyp}").into());
        }
    }

    Ok(stream)
}

// ── DNS warmup ────────────────────────────────────────────────────────────────

pub(crate) async fn dns_warmup(socks5_addr: SocketAddr, if_index: u32) {
    // Minimal A query for example.com — just to warm up the DNS-over-TCP SOCKS5 path
    let query: &[u8] = &[
        0x00, 0x01, // txn id
        0x01, 0x00, // standard query, recursion desired
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer/authority/additional
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,       // root label
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ];
    match dns_via_socks5_inner(query, socks5_addr, if_index).await {
        Ok(_) => info!("DNS warmup: success"),
        Err(e) => tracing::warn!("DNS warmup: failed: {e}"),
    }
}
