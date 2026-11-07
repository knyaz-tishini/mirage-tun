//! SOCKS5 UDP ASSOCIATE relay — the upper half of Linux UDP-over-TUN.
//!
//! `kernel_udp.rs` is the lower half: it parses raw IP/UDP packets off the
//! TUN fd and hands back `(payload, src, dst)` tuples plus a `WriteSender`
//! for injecting replies. This module is what actually moves those
//! datagrams somewhere and gets answers back — modelled on
//! `mirage-tun-windows/src/udp_socks5.rs` and `mirage-tun-macos/src/udp_forward.rs`,
//! which solve the same three problems this module has to solve too:
//!
//!   - **Per-flow session, keyed the same way**: one session per
//!     `(src_addr, dst_addr)` pair, created lazily on the first datagram and
//!     reused by every later datagram for that flow — `relay_loop` below
//!     drives the single-owner read side (`LinuxKernelUdpSocket::recv`)
//!     sequentially, so the check-existing-session-or-create-one sequence in
//!     `dispatch` has no race despite not holding the session map lock across
//!     the `.await` points.
//!   - **RFC1928 §7's control-connection lifetime**: the TCP connection used
//!     for the ASSOCIATE handshake must stay open for as long as the UDP
//!     association is wanted, or the relay tears it down. Both siblings meet
//!     this by binding the handshake stream to a variable that isn't dropped
//!     until the session task returns; `chain_session` below does the same
//!     (`_tcp_keepalive`).
//!   - **Idle expiry**: `UDP_IDLE_TIMEOUT` bounds how long a session survives
//!     with no traffic in either direction, so a DNS resolver that goes quiet
//!     doesn't hold a session (and, for the chain path, an open control
//!     connection) forever.
//!
//! What's different from both siblings, forced by what's actually available
//! in this crate:
//!   - Neither sibling's lower half looks like this crate's: both route UDP
//!     through `mirage-tcpip-stack`'s smoltcp socket, split into a
//!     `ReadHalf`/`WriteHalf` pair. This crate has no dependency on
//!     `mirage-tcpip-stack` at all (the kernel handles the IP/UDP stack; see
//!     `kernel_udp.rs`'s module doc comment) — replies are written back
//!     through `WriteSender::send_udp`, a raw-packet channel into the TUN fd.
//!   - This crate's TCP path (`src/bin/mirage2tun.rs`) marks every outbound
//!     socket it opens with `SO_MARK = BYPASS_FWMARK` so policy-routing sends
//!     it out the real NIC instead of back into the TUN device — neither
//!     sibling needs this (Windows binds to a specific interface index
//!     instead; macOS relies on pf routing). Every socket opened here (the
//!     ASSOCIATE control connection, the UDP socket that talks to the relay,
//!     and the direct-dial socket for `Bypass`) carries the same mark.
//!   - `Bypass` is handled at all: macOS's `udp_forward.rs` has no bypass
//!     path (all non-DNS UDP goes through the chain), and DNS gets no
//!     special case here either — this crate's TCP path never special-cases
//!     port 53 (`policy.decide(dst_ip, dst_port, None, None)`, no domain
//!     hint), and this module matches that exactly.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use mirage_tun_core::chains::ChainRegistry;
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::policy::{PolicyDecision, PolicyEngine};
use mirage_tun_core::traits::UdpSocket as CoreUdpSocket;

use crate::kernel_udp::{LinuxKernelUdpSocket, WriteSender};
use crate::routing::BYPASS_FWMARK;

/// A session with no traffic in either direction for this long is torn
/// down — matches both siblings' `UDP_IDLE_TIMEOUT`.
const UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-flow forwarding channel. The session task owns the actual socket
/// (direct or SOCKS5 relay); this is just how `dispatch` hands it datagrams.
struct UdpFlowSession {
    fwd_tx: mpsc::Sender<Vec<u8>>,
}

/// Key: (client src, original dst) — one entry per active UDP flow,
/// whether it's routed `Bypass` or through a chain.
type UdpFlowMap = HashMap<(SocketAddr, SocketAddr), UdpFlowSession>;

/// Shared state for the relay loop and every session task it spawns.
struct RelayState {
    sessions: Mutex<UdpFlowMap>,
    /// Chain names already reported as "not configured" for a UDP flow.
    /// `PolicyDecision::Chain(name)` naming an unregistered chain is a
    /// standing misconfiguration, not a transient failure — without this,
    /// a resolver retrying against it would put one `warn!` on stderr per
    /// datagram for as long as it keeps retrying (see the module doc
    /// comment's idle-expiry point: a session that fails to open is never
    /// inserted into `sessions`, so nothing here dedupes datagrams by
    /// itself).
    warned_missing_chain: Mutex<HashSet<String>>,
}

/// Drive the Linux kernel UDP lower half: pull parsed datagrams off `udp`
/// (the single owner of its `&mut self`, so this must be the only caller of
/// `recv()`), decide each new flow once against `policy`, and relay it
/// either direct (`Bypass`) or through a chain's SOCKS5 UDP ASSOCIATE,
/// writing replies back through `write`.
pub async fn relay_loop(
    mut udp: LinuxKernelUdpSocket,
    write: WriteSender,
    policy: Arc<PolicyEngine>,
    chains: Arc<ChainRegistry>,
    default_chain: String,
    metrics: Arc<StackMetrics>,
    cancel: CancellationToken,
) {
    let state = Arc::new(RelayState {
        sessions: Mutex::new(HashMap::new()),
        warned_missing_chain: Mutex::new(HashSet::new()),
    });

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            datagram = udp.recv() => {
                match datagram {
                    None => break,
                    Some((payload, src, dst)) => {
                        dispatch(payload, src, dst, &write, &policy, &chains, &default_chain, &metrics, &state).await;
                    }
                }
            }
        }
    }
    tracing::info!("UDP relay loop exiting");
}

/// Route one datagram: reuse an existing flow's forwarding channel, or
/// decide the flow once (`policy.decide`, exactly the TCP path's call shape)
/// and spawn the session that owns it.
async fn dispatch(
    payload: Vec<u8>,
    src: SocketAddr,
    dst: SocketAddr,
    write: &WriteSender,
    policy: &Arc<PolicyEngine>,
    chains: &Arc<ChainRegistry>,
    default_chain: &str,
    metrics: &Arc<StackMetrics>,
    state: &Arc<RelayState>,
) {
    let key = (src, dst);

    {
        let map = state.sessions.lock().await;
        if let Some(session) = map.get(&key) {
            let _ = session.fwd_tx.try_send(payload);
            return;
        }
    }

    let decision = policy.decide(dst.ip(), dst.port(), None, None).await;

    let socks5_addr = match decision {
        PolicyDecision::Bypass => None,
        PolicyDecision::Chain(ref name) => {
            let snap = chains.snapshot().await;
            match snap.get(name.as_str()).or_else(|| snap.get(default_chain)) {
                Some(entry) => Some(entry.socks5_addr),
                None => {
                    if state.warned_missing_chain.lock().await.insert(name.clone()) {
                        warn!(
                            chain = %name,
                            dst = %dst,
                            "UDP: no chain '{name}' and no default chain configured — \
                             dropping this and every further flow to it (logged once)"
                        );
                    }
                    return;
                }
            }
        }
    };

    let (fwd_tx, fwd_rx) = mpsc::channel::<Vec<u8>>(64);
    {
        let mut map = state.sessions.lock().await;
        map.insert(key, UdpFlowSession { fwd_tx: fwd_tx.clone() });
    }
    let _ = fwd_tx.try_send(payload);

    let write = write.clone();
    let metrics = Arc::clone(metrics);
    let state2 = Arc::clone(state);

    match socks5_addr {
        None => {
            tokio::spawn(async move {
                bypass_session(src, dst, fwd_rx, write, Arc::clone(&metrics)).await;
                state2.sessions.lock().await.remove(&key);
            });
        }
        Some(socks5_addr) => {
            tokio::spawn(async move {
                chain_session(src, dst, socks5_addr, fwd_rx, write, Arc::clone(&metrics)).await;
                state2.sessions.lock().await.remove(&key);
            });
        }
    }
}

// ── Bypass session: direct UDP, marked so it can't loop back into the TUN ──

/// Relay one `Bypass` UDP flow direct to `dst` from a marked socket,
/// writing replies back through `write` until idle or an error ends it.
async fn bypass_session(
    src: SocketAddr,
    dst: SocketAddr,
    mut fwd_rx: mpsc::Receiver<Vec<u8>>,
    write: WriteSender,
    metrics: Arc<StackMetrics>,
) {
    let sock = match bind_marked_udp() {
        Ok(s) => s,
        Err(e) => {
            warn!(%dst, err = %e, "UDP bypass: marked socket create failed — dropping flow");
            metrics.bypass_fail.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    metrics.bypass_ok.fetch_add(1, Ordering::Relaxed);
    metrics.active_udp.fetch_add(1, Ordering::Relaxed);

    let mut recv_buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            msg = tokio::time::timeout(UDP_IDLE_TIMEOUT, fwd_rx.recv()) => {
                match msg {
                    Ok(Some(data)) => {
                        let n = data.len() as u64;
                        if let Err(e) = sock.send_to(&data, dst).await {
                            debug!(%dst, err = %e, "UDP bypass: send failed, ending flow");
                            break;
                        }
                        metrics.bytes_tx.fetch_add(n, Ordering::Relaxed);
                    }
                    Ok(None) | Err(_) => break, // channel closed or idle timeout
                }
            }
            result = tokio::time::timeout(UDP_IDLE_TIMEOUT, sock.recv_from(&mut recv_buf)) => {
                match result {
                    Ok(Ok((n, _from))) => {
                        // Reply direction: IP src = dst (what the client dialled), IP dst = src (the client).
                        match write.send_udp(&recv_buf[..n], dst, src).await {
                            Ok(()) => {
                                metrics.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                debug!(err = %e, "UDP bypass: write back into TUN failed, ending flow");
                                break;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(%dst, err = %e, "UDP bypass: recv failed, ending flow");
                        break;
                    }
                    Err(_) => break, // idle timeout
                }
            }
        }
    }

    metrics.active_udp.fetch_sub(1, Ordering::Relaxed);
}

// ── Chain session: SOCKS5 UDP ASSOCIATE ─────────────────────────────────────

/// Relay one UDP flow through a chain's SOCKS5 UDP ASSOCIATE, keeping the
/// handshake's control connection open for the session's lifetime (RFC1928
/// §7), writing replies back through `write` until idle or an error ends it.
async fn chain_session(
    src: SocketAddr,
    dst: SocketAddr,
    socks5_addr: SocketAddr,
    mut fwd_rx: mpsc::Receiver<Vec<u8>>,
    write: WriteSender,
    metrics: Arc<StackMetrics>,
) {
    let (_tcp_keepalive, relay_addr) = match socks5_udp_associate(socks5_addr).await {
        Ok(v) => v,
        Err(e) => {
            debug!(%dst, socks5 = %socks5_addr, err = %e, "UDP chain: ASSOCIATE failed, dropping flow");
            metrics.socks5_fail.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let sock = match bind_marked_udp() {
        Ok(s) => s,
        Err(e) => {
            debug!(%dst, err = %e, "UDP chain: marked relay socket create failed, dropping flow");
            metrics.socks5_fail.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    metrics.socks5_ok.fetch_add(1, Ordering::Relaxed);
    metrics.active_udp.fetch_add(1, Ordering::Relaxed);

    let mut recv_buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            msg = tokio::time::timeout(UDP_IDLE_TIMEOUT, fwd_rx.recv()) => {
                match msg {
                    Ok(Some(data)) => {
                        let n = data.len() as u64;
                        let framed = build_socks5_udp_request(dst, &data);
                        if let Err(e) = sock.send_to(&framed, relay_addr).await {
                            debug!(%dst, relay = %relay_addr, err = %e, "UDP chain: send to relay failed, ending flow");
                            break;
                        }
                        metrics.bytes_tx.fetch_add(n, Ordering::Relaxed);
                    }
                    Ok(None) | Err(_) => break, // channel closed or idle timeout
                }
            }
            result = tokio::time::timeout(UDP_IDLE_TIMEOUT, sock.recv_from(&mut recv_buf)) => {
                match result {
                    Ok(Ok((n, _from))) => {
                        let data = &recv_buf[..n];
                        // RSV(2) + FRAG(1) + ATYP...
                        if data.len() < 4 {
                            continue;
                        }
                        match parse_socks5_udp_response(&data[3..]) {
                            Ok((header_len, real_src)) => {
                                let payload_start = 3 + header_len;
                                if payload_start > n {
                                    continue;
                                }
                                let payload = &data[payload_start..n];
                                match write.send_udp(payload, real_src, src).await {
                                    Ok(()) => {
                                        metrics.bytes_rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        debug!(err = %e, "UDP chain: write back into TUN failed, ending flow");
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(relay = %relay_addr, err = %e, "UDP chain: bad response header, dropping datagram");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(%dst, relay = %relay_addr, err = %e, "UDP chain: recv from relay failed, ending flow");
                        break;
                    }
                    Err(_) => break, // idle timeout
                }
            }
        }
    }

    metrics.active_udp.fetch_sub(1, Ordering::Relaxed);
    // `_tcp_keepalive` drops here, closing the control connection and, per
    // RFC1928 §7, ending the relay's UDP association with it.
}

// ── SOCKS5 UDP ASSOCIATE handshake + framing (RFC 1928 §7) ─────────────────

/// Perform the SOCKS5 UDP ASSOCIATE handshake (RFC 1928 §7, no-auth).
/// Returns `(control_connection, relay_udp_addr)` — the caller must keep
/// `control_connection` alive for the life of the UDP association.
async fn socks5_udp_associate(
    socks5_addr: SocketAddr,
) -> Result<(TcpStream, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = dial_marked_tcp(socks5_addr).await?;

    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err("SOCKS5 UDP ASSOCIATE: greeting rejected".into());
    }

    // UDP ASSOCIATE request — client bind addr 0.0.0.0:0 (we don't know our
    // own send-from address yet; the relay learns it from the first datagram).
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(format!("SOCKS5 UDP ASSOCIATE: bad version {}", hdr[0]).into());
    }
    if hdr[1] != 0x00 {
        return Err(format!("SOCKS5 UDP ASSOCIATE: rejected with code {}", hdr[1]).into());
    }

    let relay_addr = match hdr[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            SocketAddr::from((std::net::Ipv4Addr::from(addr), u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            SocketAddr::from((std::net::Ipv6Addr::from(addr), u16::from_be_bytes(port)))
        }
        atyp => return Err(format!("SOCKS5 UDP ASSOCIATE: unsupported bind ATYP {atyp}").into()),
    };

    Ok((stream, relay_addr))
}

/// Build a SOCKS5 §7 UDP request: `[RSV(2), FRAG(1), ATYP, ADDR, PORT, DATA]`.
fn build_socks5_udp_request(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + payload.len());
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG=0
    match dst {
        SocketAddr::V4(v4) => {
            buf.push(0x01); // ATYP IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04); // ATYP IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(payload);
    buf
}

/// Parse a SOCKS5 §7 UDP response header (starting at the ATYP byte).
/// Returns `(header_length, source_addr)` — `header_length` is how many
/// bytes of `data` the header occupies, so the caller can slice off the
/// payload that follows.
fn parse_socks5_udp_response(
    data: &[u8],
) -> Result<(usize, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    if data.is_empty() {
        return Err("empty UDP response header".into());
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                return Err("IPv4 UDP response too short".into());
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((7, SocketAddr::from((ip, port))))
        }
        0x04 => {
            if data.len() < 19 {
                return Err("IPv6 UDP response too short".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((19, SocketAddr::from((ip, port))))
        }
        atyp => Err(format!("unknown ATYP in UDP response: {atyp}").into()),
    }
}

// ── Marked sockets — same SO_MARK the TCP path uses ─────────────────────────

/// Open a TCP connection marked `SO_MARK = BYPASS_FWMARK`, exactly like
/// `dial_marked` in `src/bin/mirage2tun.rs`'s TCP path — used here for the
/// SOCKS5 ASSOCIATE control connection so it egresses the real NIC instead
/// of looping back into the TUN device via policy routing.
async fn dial_marked_tcp(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    #[cfg(target_os = "linux")]
    sock.set_mark(BYPASS_FWMARK)?;
    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    tokio::net::TcpSocket::from_std_stream(std_stream).connect(addr).await
}

/// Open a UDP socket marked `SO_MARK = BYPASS_FWMARK` — used for both the
/// direct `Bypass` send/recv socket and the socket that talks to a chain's
/// SOCKS5 relay address, for the same reason `dial_marked_tcp` above marks
/// the control connection.
fn bind_marked_udp() -> std::io::Result<tokio::net::UdpSocket> {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    #[cfg(target_os = "linux")]
    sock.set_mark(BYPASS_FWMARK)?;
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().expect("static addr is valid");
    sock.bind(&bind_addr.into())?;
    sock.set_nonblocking(true)?;
    let std_udp: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_udp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_udp_request_roundtrip_v4() {
        let dst: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");
        let payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let framed = build_socks5_udp_request(dst, payload);

        assert_eq!(&framed[..3], &[0x00, 0x00, 0x00]);
        assert_eq!(framed[3], 0x01);
        let (header_len, parsed_addr) = parse_socks5_udp_response(&framed[3..]).expect("parses");
        assert_eq!(parsed_addr, dst);
        assert_eq!(&framed[3 + header_len..], payload);
    }

    #[test]
    fn socks5_udp_request_roundtrip_v6() {
        let dst: SocketAddr = "[2001:db8::1]:443".parse().expect("valid addr");
        let payload = b"hello";
        let framed = build_socks5_udp_request(dst, payload);

        assert_eq!(framed[3], 0x04);
        let (header_len, parsed_addr) = parse_socks5_udp_response(&framed[3..]).expect("parses");
        assert_eq!(parsed_addr, dst);
        assert_eq!(&framed[3 + header_len..], payload);
    }

    #[test]
    fn parse_socks5_udp_response_rejects_empty() {
        assert!(parse_socks5_udp_response(&[]).is_err());
    }

    #[test]
    fn parse_socks5_udp_response_rejects_unknown_atyp() {
        assert!(parse_socks5_udp_response(&[0x03, 0x00]).is_err());
    }

    #[test]
    fn parse_socks5_udp_response_rejects_truncated_ipv4() {
        // ATYP=1 but fewer than the 4 address + 2 port bytes it promises.
        assert!(parse_socks5_udp_response(&[0x01, 0x08, 0x08]).is_err());
    }

    #[test]
    fn flow_key_distinguishes_by_both_src_and_dst() {
        let a: SocketAddr = "10.0.0.2:5000".parse().expect("valid addr");
        let b: SocketAddr = "10.0.0.2:5001".parse().expect("valid addr");
        let dst: SocketAddr = "8.8.8.8:53".parse().expect("valid addr");

        let mut map: UdpFlowMap = HashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        map.insert((a, dst), UdpFlowSession { fwd_tx: tx.clone() });
        assert!(map.get(&(a, dst)).is_some());
        assert!(map.get(&(b, dst)).is_none());
    }
}
