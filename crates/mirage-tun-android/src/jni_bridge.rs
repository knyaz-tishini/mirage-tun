//! JNI entry points called from Kotlin `MirageNative`.
//!
//! All functions are gated with `#[cfg(target_os = "android")]`.
//! Non-Android builds compile empty stubs so the crate can be
//! `cargo check`-ed on Windows during development.
//!
//! # Kotlin companion class
//! ```kotlin
//! package com.mirage.vpn
//! object MirageNative {
//!     external fun start(fd: Int, configJson: String): Boolean
//!     external fun stop()
//!     external fun updateChains(json: String)
//!     external fun setVpnService(vpnService: VpnService)
//!     init { System.loadLibrary("mirage2tun") }
//! }
//! ```

use std::sync::OnceLock;

/// Pending TUN fd — set before `start()` launches the tokio runtime.
/// `stack.rs` calls `take_pending_fd()` during `TunStack::start()`.
static PENDING_FD: OnceLock<std::sync::Mutex<Option<i32>>> = OnceLock::new();

/// Consume the fd stored by the JNI `start` function.
pub(crate) fn take_pending_fd() -> Option<i32> {
    PENDING_FD
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

#[cfg(target_os = "android")]
fn store_pending_fd(fd: i32) {
    *PENDING_FD
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(fd);
}

// ── Android-only JNI functions ────────────────────────────────────────────────

#[cfg(target_os = "android")]
mod android {
    use super::store_pending_fd;

    use std::net::SocketAddr;
    use std::sync::Arc;

    use jni::{
        objects::{JClass, JObject, JString},
        sys::{jboolean, jint, JNI_FALSE, JNI_TRUE},
        JNIEnv,
    };
    use serde::Deserialize;
    use tokio::sync::{mpsc, Mutex};
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info, warn};

    use crate::{
        error::AndroidTunError,
        stack::AndroidTunStack,
        vpn_service::SocketProtector,
    };
    use mirage_tun_core::{
        chains::{ChainConfig, ChainMap, ChainRegistry},
        policy::PolicyConfigRequest,
        stack_config::{ChainEntry, StackConfig},
        traits::{TcpAcceptor, TunStack, UdpSocket},
    };

    // ── JSON DTO for start() config ───────────────────────────────────────────
    //
    // StackConfig has no Deserialize — we use a local DTO and convert.

    #[derive(Deserialize)]
    struct StartConfigDto {
        #[serde(default = "default_tun_addr")]
        tun_addr: String,
        #[serde(default = "default_mtu")]
        mtu: u16,
        #[serde(default)]
        chains: Vec<ChainConfigDto>,
        #[serde(default)]
        policy: Option<PolicyConfigRequest>,
        // kill_switch removed from StackConfig (selective now); field kept for config compat, ignored.
        #[serde(default, rename = "kill_switch")]
        _kill_switch_compat: Option<bool>,
        #[serde(default)]
        relay_addrs: Vec<std::net::IpAddr>,
        #[serde(default = "default_dns_upstream")]
        dns_upstream: SocketAddr,
        #[serde(default = "default_dns_cache_ttl")]
        dns_cache_ttl_secs: u64,
        #[serde(default = "default_dns_cache_max")]
        dns_cache_max: usize,
        #[serde(default = "default_concurrency")]
        dns_concurrency: usize,
        #[serde(default = "default_concurrency")]
        socks5_concurrency: usize,
        #[serde(default)]
        per_chain_tun: bool,
    }

    #[derive(Deserialize, Clone)]
    struct ChainConfigDto {
        name: String,
        socks5_addr: String,
    }

    fn default_tun_addr() -> String { "10.0.85.1/24".to_owned() }
    fn default_mtu() -> u16 { 1500 }
    fn default_dns_upstream() -> SocketAddr { "8.8.8.8:53".parse().expect("static addr is valid") }
    fn default_dns_cache_ttl() -> u64 { 300 }
    fn default_dns_cache_max() -> usize { 4096 }
    fn default_concurrency() -> usize { 64 }

    impl StartConfigDto {
        fn into_stack_config(self) -> Result<(StackConfig, Vec<ChainConfigDto>), AndroidTunError> {
            let chain_dtos = self.chains.clone();
            let chains: Vec<ChainEntry> = self
                .chains
                .iter()
                .filter_map(|c| {
                    match c.socks5_addr.parse::<SocketAddr>() {
                        Ok(addr) => Some(ChainEntry { name: c.name.clone(), socks5_addr: addr, group: None }),
                        Err(e) => {
                            warn!("start: invalid socks5_addr '{}' for chain '{}': {e}", c.socks5_addr, c.name);
                            None
                        }
                    }
                })
                .collect();

            let policy = self.policy.unwrap_or_else(|| PolicyConfigRequest {
                rules: vec![],
                default_action: mirage_tun_core::policy::PolicyDecision::default_chain(),
            });

            Ok((StackConfig {
                tun_name: "tun0".to_owned(),
                tun_addr: self.tun_addr,
                mtu: self.mtu,
                chains,
                policy,
                chain_dns: vec![],
                relay_addrs: self.relay_addrs,
                dns_upstream: self.dns_upstream,
                dns_cache_ttl_secs: self.dns_cache_ttl_secs,
                dns_cache_max: self.dns_cache_max,
                dns_concurrency: self.dns_concurrency,
                socks5_concurrency: self.socks5_concurrency,
                per_chain_tun: self.per_chain_tun,
            }, chain_dtos))
        }
    }

    // ── Global runtime state ──────────────────────────────────────────────────

    struct RunState {
        cancel: CancellationToken,
        protector: Arc<SocketProtector>,
        /// Sender for hot-reloading chains at runtime.
        chain_tx: mpsc::Sender<Vec<ChainConfig>>,
    }

    static RUN_STATE: std::sync::OnceLock<std::sync::Mutex<Option<RunState>>> =
        std::sync::OnceLock::new();

    fn run_state() -> &'static std::sync::Mutex<Option<RunState>> {
        RUN_STATE.get_or_init(|| std::sync::Mutex::new(None))
    }

    // ── Pre-start VpnService cell ─────────────────────────────────────────────
    //
    // Kotlin calls setVpnService() before start(). We store the protector here
    // so start() can pick it up.

    static PRE_START_PROTECTOR: std::sync::OnceLock<std::sync::Mutex<Option<SocketProtector>>> =
        std::sync::OnceLock::new();

    fn pre_start_protector() -> &'static std::sync::Mutex<Option<SocketProtector>> {
        PRE_START_PROTECTOR.get_or_init(|| std::sync::Mutex::new(None))
    }

    // ── TCP relay: smoltcp stream → SOCKS5 proxy ──────────────────────────────

    async fn run_tcp_loop<T: TcpAcceptor>(
        mut acceptor: T,
        registry: Arc<ChainRegistry>,
        protector: Arc<SocketProtector>,
        cancel: CancellationToken,
    ) {
        loop {
            let accepted = tokio::select! {
                _ = cancel.cancelled() => break,
                conn = acceptor.accept() => conn,
            };

            let (mut app_stream, _local, remote) = match accepted {
                Some(t) => t,
                None => break,
            };

            let chains = registry.snapshot().await;
            let proxy_addr = match chains.get("default").copied() {
                Some(a) => a,
                None => {
                    warn!("tcp: no 'default' chain configured, dropping connection to {remote}");
                    continue;
                }
            };

            let protector = Arc::clone(&protector);

            tokio::spawn(async move {
                // Connect to the SOCKS5 proxy.
                let proxy_tcp = match tokio::net::TcpStream::connect(proxy_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("tcp: connect to proxy {proxy_addr} failed: {e}");
                        return;
                    }
                };

                // Exempt the proxy socket from VPN capture BEFORE any data flows.
                #[cfg(target_os = "android")]
                {
                    use std::os::unix::io::AsRawFd;
                    if let Err(e) = protector.protect(proxy_tcp.as_raw_fd()) {
                        error!("tcp: protect(fd) failed: {e}");
                        return;
                    }
                }
                // On non-Android builds SocketProtector::protect() is a no-op, but
                // we still need to suppress "unused variable" for protector.
                #[cfg(not(target_os = "android"))]
                let _ = &protector;

                let mut proxy_tcp = proxy_tcp;

                // SOCKS5 handshake — no-auth (method 0x00).
                // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
                let greeting = [0x05u8, 0x01, 0x00];
                if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut proxy_tcp, &greeting).await {
                    error!("tcp: socks5 greeting write: {e}");
                    return;
                }
                let mut method_resp = [0u8; 2];
                if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut proxy_tcp, &mut method_resp).await {
                    error!("tcp: socks5 greeting read: {e}");
                    return;
                }
                if method_resp[0] != 0x05 || method_resp[1] == 0xFF {
                    error!("tcp: socks5 auth rejected by proxy {proxy_addr}");
                    return;
                }

                // CONNECT request.
                let req = build_socks5_connect_request(remote);
                if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut proxy_tcp, &req).await {
                    error!("tcp: socks5 connect request write: {e}");
                    return;
                }

                // Read CONNECT response (10 bytes for IPv4, 22 for IPv6, variable for domain).
                let mut resp_hdr = [0u8; 10];
                if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut proxy_tcp, &mut resp_hdr).await {
                    error!("tcp: socks5 connect response read: {e}");
                    return;
                }
                if resp_hdr[1] != 0x00 {
                    error!("tcp: socks5 CONNECT refused, code={}", resp_hdr[1]);
                    return;
                }
                // Consume any remaining BND address bytes.
                match resp_hdr[3] {
                    0x04 => {
                        // IPv6: already read 4 bytes of it; need 12 more + 2 port.
                        let mut tail = [0u8; 12];
                        if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut proxy_tcp, &mut tail).await {
                            error!("tcp: socks5 ipv6 tail read: {e}");
                            return;
                        }
                    }
                    0x03 => {
                        // Domain — length byte already consumed in resp_hdr[4].
                        let domain_len = resp_hdr[4] as usize;
                        // We already read up to byte index 9. Domain starts at index 4.
                        // Bytes already consumed: domain_len is at [4], then domain_len bytes,
                        // then 2 port bytes. We have read indices 0..9 (10 bytes total).
                        // Remaining after resp_hdr: max(0, (4 + 1 + domain_len + 2) - 10)
                        let total_resp = 4 + 1 + domain_len + 2;
                        if total_resp > 10 {
                            let mut tail = vec![0u8; total_resp - 10];
                            if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut proxy_tcp, &mut tail).await {
                                error!("tcp: socks5 domain tail read: {e}");
                                return;
                            }
                        }
                    }
                    _ => {} // 0x01 IPv4 — all 10 bytes already consumed.
                }

                // Relay bidirectionally.
                if let Err(e) = tokio::io::copy_bidirectional(&mut app_stream, &mut proxy_tcp).await {
                    if e.kind() != std::io::ErrorKind::BrokenPipe
                        && e.kind() != std::io::ErrorKind::ConnectionReset
                    {
                        error!("tcp relay {remote}: {e}");
                    }
                }
            });
        }
    }

    /// Build a SOCKS5 CONNECT request for `target`.
    fn build_socks5_connect_request(target: SocketAddr) -> Vec<u8> {
        let mut req = Vec::with_capacity(22);
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

    // ── UDP relay: smoltcp datagram → SOCKS5 UDP associate ───────────────────

    async fn run_udp_loop<U: UdpSocket>(
        mut socket: U,
        registry: Arc<ChainRegistry>,
        protector: Arc<SocketProtector>,
        cancel: CancellationToken,
    ) {
        loop {
            let packet = tokio::select! {
                _ = cancel.cancelled() => break,
                p = socket.recv() => p,
            };

            let (payload, src, dst) = match packet {
                Some(p) => p,
                None => break,
            };

            let chains = registry.snapshot().await;
            let proxy_addr = match chains.get("default").copied() {
                Some(a) => a,
                None => {
                    warn!("udp: no 'default' chain configured, dropping datagram to {dst}");
                    continue;
                }
            };

            let protector = Arc::clone(&protector);

            tokio::spawn(async move {
                if let Err(e) = relay_udp_via_socks5(payload, src, dst, proxy_addr, protector).await {
                    error!("udp relay {src}→{dst}: {e}");
                }
            });
        }
    }

    async fn relay_udp_via_socks5(
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
        proxy_addr: SocketAddr,
        protector: Arc<SocketProtector>,
    ) -> Result<(), AndroidTunError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Open a TCP control connection for UDP ASSOCIATE.
        let mut ctrl = tokio::net::TcpStream::connect(proxy_addr).await?;

        #[cfg(target_os = "android")]
        {
            use std::os::unix::io::AsRawFd;
            protector.protect(ctrl.as_raw_fd())?;
        }
        #[cfg(not(target_os = "android"))]
        let _ = &protector;

        // No-auth greeting.
        ctrl.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        ctrl.read_exact(&mut resp).await?;
        if resp[1] == 0xFF {
            return Err(AndroidTunError::Other("socks5 udp: auth rejected".to_owned()));
        }

        // UDP ASSOCIATE request — we don't bind locally, send zero address/port.
        let assoc_req = match src {
            SocketAddr::V4(_) => vec![0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            SocketAddr::V6(_) => {
                let mut r = vec![0x05u8, 0x03, 0x00, 0x04];
                r.extend_from_slice(&[0u8; 16]);
                r.extend_from_slice(&[0u8; 2]);
                r
            }
        };
        ctrl.write_all(&assoc_req).await?;

        let mut assoc_resp = [0u8; 10];
        ctrl.read_exact(&mut assoc_resp).await?;
        if assoc_resp[1] != 0x00 {
            return Err(AndroidTunError::Other(format!(
                "socks5 udp associate refused, code={}",
                assoc_resp[1]
            )));
        }

        // BND address — where to send UDP datagrams.
        let udp_relay_addr: SocketAddr = match assoc_resp[3] {
            0x01 => {
                // IPv4
                let port = u16::from_be_bytes([assoc_resp[8], assoc_resp[9]]);
                let ip = std::net::Ipv4Addr::new(
                    assoc_resp[4], assoc_resp[5], assoc_resp[6], assoc_resp[7],
                );
                SocketAddr::from((ip, port))
            }
            0x04 => {
                // IPv6 — need 12 more bytes + 2 port after the first 10.
                let mut tail = [0u8; 14];
                ctrl.read_exact(&mut tail).await?;
                let port = u16::from_be_bytes([tail[12], tail[13]]);
                let mut octets = [0u8; 16];
                octets[..4].copy_from_slice(&assoc_resp[4..8]);
                octets[4..].copy_from_slice(&tail[..12]);
                let ip = std::net::Ipv6Addr::from(octets);
                SocketAddr::from((ip, port))
            }
            t => {
                return Err(AndroidTunError::Other(format!(
                    "socks5 udp: unsupported BND atyp {t}"
                )));
            }
        };

        // Bind a local UDP socket, protect it, and send the framed datagram.
        let udp_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

        #[cfg(target_os = "android")]
        {
            use std::os::unix::io::AsRawFd;
            protector.protect(udp_sock.as_raw_fd())?;
        }

        udp_sock.connect(udp_relay_addr).await?;

        // Build SOCKS5 UDP request header.
        let frame = build_socks5_udp_frame(&payload, dst);
        udp_sock.send(&frame).await?;

        // Control connection stays open until we drop it here — proxy will
        // tear down the UDP association when the TCP control conn closes.
        drop(ctrl);
        Ok(())
    }

    /// Build a SOCKS5 UDP request header + payload.
    fn build_socks5_udp_frame(payload: &[u8], dst: SocketAddr) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 22);
        frame.extend_from_slice(&[0x00, 0x00]); // RSV
        frame.push(0x00); // FRAG = 0 (no fragmentation)
        match dst {
            SocketAddr::V4(v4) => {
                frame.push(0x01);
                frame.extend_from_slice(&v4.ip().octets());
                frame.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                frame.push(0x04);
                frame.extend_from_slice(&v6.ip().octets());
                frame.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        frame
    }

    // ── JNI: start ────────────────────────────────────────────────────────────

    /// Called from Kotlin to start the VPN stack.
    ///
    /// ```kotlin
    /// MirageNative.start(fd = pfd.fd, configJson = json)
    /// ```
    ///
    /// Returns `true` on success, `false` on failure.
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_start(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        fd: jint,
        config_json: JString<'_>,
    ) -> jboolean {
        let config_str: String = match env.get_string(&config_json) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("start: get_string failed: {e}");
                return JNI_FALSE;
            }
        };

        let dto: StartConfigDto = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(e) => {
                error!("start: config JSON parse failed: {e}");
                return JNI_FALSE;
            }
        };

        {
            let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
            if state.is_some() {
                error!("start: already running");
                return JNI_FALSE;
            }

            // Build chain registry for hot-reload.
            let chain_configs: Vec<ChainConfig> = dto
                .chains
                .iter()
                .map(|c| ChainConfig {
                    name: c.name.clone(),
                    socks5_addr: c.socks5_addr.clone(),
                    dns_upstream: None,
                    protocol: mirage_tun_core::chains::ChainProtocol::Socks5,
                })
                .collect();

            let (cfg, _chain_dtos) = match dto.into_stack_config() {
                Ok(pair) => pair,
                Err(e) => {
                    error!("start: config conversion failed: {e}");
                    return JNI_FALSE;
                }
            };

            let cancel = CancellationToken::new();
            let cancel_clone = cancel.clone();

            // Store fd so TunStack::start() can retrieve it.
            store_pending_fd(fd);

            // Pick up the pre-registered protector (set via setVpnService) or
            // fall back to a no-op one if the caller skipped setVpnService.
            let protector = {
                let mut guard = pre_start_protector()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.take().unwrap_or_else(SocketProtector::new)
            };
            let protector = Arc::new(protector);

            let (chain_tx, mut chain_rx) = mpsc::channel::<Vec<ChainConfig>>(8);

            let registry = Arc::new(ChainRegistry::new(chain_configs));
            let registry_bg = Arc::clone(&registry);
            let protector_tcp = Arc::clone(&protector);
            let protector_udp = Arc::clone(&protector);

            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("mirage-android")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("start: tokio runtime build failed: {e}");
                    return JNI_FALSE;
                }
            };

            let result: Result<(), AndroidTunError> = rt.block_on(async move {
                let handle = AndroidTunStack::start(cfg, cancel_clone.clone()).await?;

                let tcp_acceptor = handle.tcp;
                let udp_socket = handle.udp;

                // Background task: update chain registry from hot-reload channel.
                let registry_reload = Arc::clone(&registry_bg);
                tokio::spawn(async move {
                    while let Some(new_configs) = chain_rx.recv().await {
                        let mut new_map = ChainMap::new();
                        for cfg in new_configs {
                            match cfg.socks5_addr.parse::<SocketAddr>() {
                                Ok(addr) => { new_map.insert(cfg.name, addr); }
                                Err(e) => warn!("chains reload: invalid addr: {e}"),
                            }
                        }
                        registry_reload.update(new_map).await;
                        info!("chains: hot-reload applied");
                    }
                });

                // TCP relay loop.
                let reg_tcp = Arc::clone(&registry_bg);
                let cancel_tcp = cancel_clone.clone();
                tokio::spawn(async move {
                    run_tcp_loop(tcp_acceptor, reg_tcp, protector_tcp, cancel_tcp).await;
                });

                // UDP relay loop.
                let reg_udp = Arc::clone(&registry_bg);
                let cancel_udp = cancel_clone.clone();
                tokio::spawn(async move {
                    run_udp_loop(udp_socket, reg_udp, protector_udp, cancel_udp).await;
                });

                Ok(())
            });

            match result {
                Ok(()) => {
                    *state = Some(RunState {
                        cancel,
                        protector,
                        chain_tx,
                    });
                    info!("start: VPN stack up");
                    JNI_TRUE
                }
                Err(e) => {
                    error!("start: stack failed: {e}");
                    JNI_FALSE
                }
            }
        }
    }

    // ── JNI: stop ─────────────────────────────────────────────────────────────

    /// Called from Kotlin to stop the VPN stack.
    ///
    /// ```kotlin
    /// MirageNative.stop()
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_stop(
        _env: JNIEnv<'_>,
        _class: JClass<'_>,
    ) {
        let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = state.take() {
            s.cancel.cancel();
            info!("stop: cancellation sent");
        }
    }

    // ── JNI: updateChains ─────────────────────────────────────────────────────

    /// Hot-reload chain list without restarting the stack.
    ///
    /// ```kotlin
    /// MirageNative.updateChains(json = "[{\"name\":\"default\",\"socks5_addr\":\"1.2.3.4:1080\"}, ...]")
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_updateChains(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        json: JString<'_>,
    ) {
        let json_str: String = match env.get_string(&json) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("updateChains: get_string failed: {e}");
                return;
            }
        };

        let entries: Vec<ChainConfig> = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(e) => {
                error!("updateChains: JSON parse failed: {e}");
                return;
            }
        };

        let state = run_state().lock().unwrap_or_else(|e| e.into_inner());
        match state.as_ref() {
            Some(s) => {
                if s.chain_tx.try_send(entries).is_err() {
                    warn!("updateChains: channel full or closed, update dropped");
                }
            }
            None => {
                warn!("updateChains: stack not running, update ignored");
            }
        }
    }

    // ── JNI: setVpnService ────────────────────────────────────────────────────

    /// Pass the Kotlin `VpnService` instance to Rust so `protect(fd)` can be called.
    ///
    /// ```kotlin
    /// MirageNative.setVpnService(this)   // `this` = VpnService instance
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_setVpnService(
        env: JNIEnv<'_>,
        _class: JClass<'_>,
        vpn_service: JObject<'_>,
    ) {
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                error!("setVpnService: get_java_vm failed: {e}");
                return;
            }
        };
        let global_ref = match env.new_global_ref(vpn_service) {
            Ok(r) => r,
            Err(e) => {
                error!("setVpnService: new_global_ref failed: {e}");
                return;
            }
        };

        let protector = SocketProtector::new(vm, global_ref);

        // If the stack is already running, update protector in-place.
        // If not yet running, store for pickup by start().
        let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = state.as_mut() {
            // Arc<SocketProtector> is shared with running tasks — we can't replace it.
            // The running tasks will use the existing protector; this new one is stored
            // for any future restart cycle.
            warn!("setVpnService: stack already running; new protector stored for next start");
        }
        drop(state);

        // Always update the pre-start cell so the next start() picks it up.
        let mut guard = pre_start_protector()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(protector);
    }
}

// ── Non-Android stubs ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
mod stubs {
    // Empty — on non-Android builds the JNI functions are not exposed.
    // `cargo check` on Windows validates the rest of the crate compiles.
}
