//! Raw-IP datapath: whole IP packets between the Wintun adapter and the
//! GUI client.
//!
//! In this mode mirage2tun terminates nothing.  It reads raw IP packets out
//! of the Wintun adapter, hands them to the client and writes the packets
//! that come back into the adapter.  The client puts them into QUIC
//! datagrams; the box is a plain L3 forwarder.
//!
//! The client is reached over a local TCP socket that speaks a small
//! SOCKS5-derived protocol:
//!
//! ```text
//! greeting (client -> server): 05 01 00
//! greeting (server -> client): 05 00
//! request  (client -> server): 05 05 00 03 09 "mirage-ip" 00 00
//! reply    (server -> client): 05 00 <RSV ATYP ADDR [PORT]>
//! ```
//!
//! After the reply the socket carries frames in both directions:
//! `[2 bytes big-endian length][the IP packet bytes]`.

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::chains::{ChainProtocol, ChainRegistry, ResolvedChain};
use crate::config::TunConfig;
use crate::error::TunError;
use crate::wintun::WintunDevice;

// -- Local raw-IP protocol constants -------------------------------------

/// SOCKS5 version byte.
const PROTO_VERSION: u8 = 0x05;

/// SOCKS5 command: raw IP tunnel.
const CMD_RAW_IP: u8 = 0x05;

/// SOCKS5 address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;

/// SOCKS5 address type: IPv4.
const ATYP_IPV4: u8 = 0x01;

/// SOCKS5 address type: IPv6.
const ATYP_IPV6: u8 = 0x04;

/// Domain name sent in the raw-IP request.
const RAW_IP_DOMAIN: &str = "mirage-ip";

/// Port sent in the raw-IP request - unused for raw IP.
const RAW_IP_PORT: u16 = 0;

/// Delay between reconnect attempts.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// How often the counters are logged.
const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// Upper bound for the whole handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the reply tail.  A peer that answers with the code
/// only (`05 00`) is accepted as well.
const REPLY_TAIL_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait for the optional bound port of the reply.
const REPLY_PORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Error type of the frame codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum FrameError {
    #[error("truncated frame: need {needed} bytes, have {have}")]
    Truncated { needed: usize, have: usize },
    #[error("frame length {len} exceeds the {limit} byte limit")]
    TooLarge { len: u16, limit: u16 },
}

/// One decoded frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    /// A complete IP packet.
    Packet(Vec<u8>),
    /// The frame body exceeded the MTU and was discarded.
    TooLarge(u16),
    /// A zero-length frame - there is nothing to forward.
    Empty,
}

/// Encode one IP packet into a length-prefixed frame.
pub(crate) fn encode_frame(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + packet.len());
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

/// Decode one frame from the head of `buf`.
///
/// Returns the frame and the number of bytes it occupied in `buf`.
pub(crate) fn decode_frame(
    buf: &[u8],
    limit: u16,
) -> std::result::Result<(Frame, usize), FrameError> {
    if buf.len() < 2 {
        return Err(FrameError::Truncated {
            needed: 2,
            have: buf.len(),
        });
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]);
    if len > limit {
        return Err(FrameError::TooLarge { len, limit });
    }
    let frame_len = 2 + len as usize;
    if buf.len() < frame_len {
        return Err(FrameError::Truncated {
            needed: frame_len,
            have: buf.len(),
        });
    }
    if len == 0 {
        return Ok((Frame::Empty, frame_len));
    }
    Ok((Frame::Packet(buf[2..frame_len].to_vec()), frame_len))
}

/// Counters of the raw-IP datapath.
#[derive(Default)]
pub struct RawIpStats {
    /// Packets handed to the client (Wintun -> socket).
    pub to_client: AtomicU64,
    /// Packets received from the client (socket -> Wintun).
    pub from_client: AtomicU64,
    /// Packets dropped because they exceed the MTU.
    pub dropped_oversize: AtomicU64,
    /// Frames that could not be forwarded.
    pub malformed: AtomicU64,
    /// Reconnect attempts after a broken socket.
    pub reconnects: AtomicU64,
    /// Writes into the Wintun adapter that failed.
    pub write_errors: AtomicU64,
    /// Socket reads and writes that failed.
    pub io_errors: AtomicU64,
}

/// Raw-IP runner: forwards whole IP packets between Wintun and the client.
pub struct RawIpRunner {
    /// Number of live client connections - used for graceful drain.
    pub active_conns: Arc<AtomicU64>,
    /// Shared counters of the datapath.
    pub stats: Arc<RawIpStats>,
}

impl RawIpRunner {
    /// Start the raw-IP datapath.
    ///
    /// The runner takes over the Wintun channels and keeps one TCP
    /// connection to the client open.  A broken connection is re-dialed
    /// every second - the client may not have a live tunnel yet - so the
    /// pump only stops when the cancellation token fires.
    pub async fn start(
        device: WintunDevice,
        chain_registry: Arc<ChainRegistry>,
        cancel: CancellationToken,
        if_index: u32,
        cfg: &TunConfig,
    ) -> crate::error::Result<Self> {
        let (wintun_rx, wintun_tx) = device.take_channels();
        let stats = Arc::new(RawIpStats::default());
        let active_conns = Arc::new(AtomicU64::new(0));
        let mtu = cfg.mtu;

        // Resolve the chain once up-front so a misconfigured registry fails
        // fast instead of looping silently.
        let chains = chain_registry.resolved_snapshot().await;
        let selected = select_raw_chain(&chains).ok_or_else(|| {
            TunError::Other("raw_ip mode: no chain configured".to_owned())
        })?;
        info!(
            "RawIpRunner: started, chain={}, addr={}, protocol={:?}, mtu={mtu}",
            selected.entry.chain_id, selected.entry.socks5_addr, selected.protocol
        );

        let stats2 = Arc::clone(&stats);
        let active2 = Arc::clone(&active_conns);
        let registry2 = Arc::clone(&chain_registry);
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            run_loop(
                wintun_rx,
                wintun_tx,
                registry2,
                cancel2,
                if_index,
                mtu,
                stats2,
                active2,
            )
            .await;
        });

        // Stats printer.
        let stats3 = Arc::clone(&stats);
        let cancel3 = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel3.cancelled() => break,
                    _ = tokio::time::sleep(STATS_INTERVAL) => {
                        let s = &stats3;
                        info!(
                            "rawip stats: to_client={} from_client={} dropped_oversize={} malformed={} reconnects={} write_errors={} io_errors={}",
                            s.to_client.load(Ordering::Relaxed),
                            s.from_client.load(Ordering::Relaxed),
                            s.dropped_oversize.load(Ordering::Relaxed),
                            s.malformed.load(Ordering::Relaxed),
                            s.reconnects.load(Ordering::Relaxed),
                            s.write_errors.load(Ordering::Relaxed),
                            s.io_errors.load(Ordering::Relaxed),
                        );
                    }
                }
            }
        });

        Ok(Self {
            active_conns,
            stats,
        })
    }
}

/// Pick the chain that speaks the raw-IP protocol.
///
/// The raw-IP chain wins.  When no chain is marked, the first chain in
/// priority order is used - the client may still speak the raw protocol
/// without declaring it.
pub(crate) fn select_raw_chain(chains: &[ResolvedChain]) -> Option<&ResolvedChain> {
    chains
        .iter()
        .find(|c| c.protocol == ChainProtocol::RawIp)
        .or_else(|| chains.first())
}

// -- Reconnect loop ------------------------------------------------------

/// Keep a client connection alive until the runner is cancelled.
async fn run_loop(
    mut wintun_rx: Receiver<Vec<u8>>,
    wintun_tx: Sender<Vec<u8>>,
    registry: Arc<ChainRegistry>,
    cancel: CancellationToken,
    if_index: u32,
    mtu: u16,
    stats: Arc<RawIpStats>,
    active_conns: Arc<AtomicU64>,
) {
    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Resolve the chain for this attempt: the raw-IP chain wins,
        // otherwise the first chain in priority order.
        let chains = registry.resolved_snapshot().await;
        let Some(selected) = select_raw_chain(&chains) else {
            warn!("rawip: no chain configured - retrying in {}s", RECONNECT_DELAY.as_secs());
            if wait_retry(&cancel).await {
                break;
            }
            continue;
        };
        let addr = selected.entry.socks5_addr;
        let chain_id = selected.entry.chain_id.clone();

        let result = connect_and_pump(
            addr,
            chain_id,
            if_index,
            mtu,
            &mut wintun_rx,
            &wintun_tx,
            &stats,
            &active_conns,
            &cancel,
        )
        .await;
        if let Err(e) = result {
            warn!("rawip: connection to {addr} failed: {e}");
        }

        if cancel.is_cancelled() {
            break;
        }
        stats.reconnects.fetch_add(1, Ordering::Relaxed);
        info!(
            "rawip: reconnecting to {addr} in {}s",
            RECONNECT_DELAY.as_secs()
        );
        if wait_retry(&cancel).await {
            break;
        }
    }
    info!("rawip: runner stopped");
}

/// Sleep before the next dial.  Returns true when the runner must stop.
async fn wait_retry(cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(RECONNECT_DELAY) => false,
    }
}

/// Dial the client, shake hands and pump packets until the socket breaks.
async fn connect_and_pump(
    addr: SocketAddr,
    chain_id: String,
    if_index: u32,
    mtu: u16,
    wintun_rx: &mut Receiver<Vec<u8>>,
    wintun_tx: &Sender<Vec<u8>>,
    stats: &RawIpStats,
    active_conns: &AtomicU64,
    cancel: &CancellationToken,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // A loopback client is reached directly, everything else leaves through
    // the original interface so the connection does not enter the tunnel.
    let effective_if = if addr.ip().is_loopback() { 0 } else { if_index };
    let mut stream = crate::ipstack::connect_via_interface(addr, effective_if).await?;
    handshake(&mut stream).await?;
    info!("rawip: connected to {addr} (chain '{chain_id}')");
    active_conns.fetch_add(1, Ordering::Relaxed);

    let (mut reader, mut writer) = tokio::io::split(stream);

    let to_socket = pump_wintun_to_socket(wintun_rx, &mut writer, stats, mtu);
    let to_wintun = pump_socket_to_wintun(&mut reader, wintun_tx, stats, mtu);
    tokio::pin!(to_socket);
    tokio::pin!(to_wintun);

    let result = tokio::select! {
        r = &mut to_socket => r.map(|_| ()),
        r = &mut to_wintun => r.map(|_| ()),
        _ = cancel.cancelled() => Ok(()),
    };

    active_conns.fetch_sub(1, Ordering::Relaxed);
    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

// -- Handshake -----------------------------------------------------------

/// Run the raw-IP handshake on an open socket.
async fn handshake(
    stream: &mut TcpStream,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_inner(stream)).await??;
    Ok(())
}

async fn handshake_inner(
    stream: &mut TcpStream,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Greeting: VER=05, one method, method=00 (no authentication).
    stream.write_all(&[PROTO_VERSION, 0x01, 0x00]).await?;

    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != PROTO_VERSION || greeting[1] != 0x00 {
        return Err(format!(
            "raw-ip greeting rejected: {:02x} {:02x}",
            greeting[0], greeting[1]
        )
        .into());
    }

    // Request: VER=05, CMD=05 (raw IP), RSV=00, ATYP=03 (domain),
    // LEN=09, "mirage-ip", PORT=0000.
    let mut request = Vec::with_capacity(4 + 1 + RAW_IP_DOMAIN.len() + 2);
    request.push(PROTO_VERSION);
    request.push(CMD_RAW_IP);
    request.push(0x00);
    request.push(ATYP_DOMAIN);
    request.push(RAW_IP_DOMAIN.len() as u8);
    request.extend_from_slice(RAW_IP_DOMAIN.as_bytes());
    request.extend_from_slice(&RAW_IP_PORT.to_be_bytes());
    stream.write_all(&request).await?;

    // Reply: VER=05, REP=00 and a bound address that is ignored - only the
    // code matters.
    let mut code = [0u8; 2];
    stream.read_exact(&mut code).await?;
    if code[0] != PROTO_VERSION {
        return Err(format!("raw-ip reply has a bad version: {}", code[0]).into());
    }
    if code[1] != 0x00 {
        return Err(format!("raw-ip request rejected, code: {}", code[1]).into());
    }

    // The bound address is advisory.  It is read when the peer sends it
    // and skipped when it does not.
    let mut tail = [0u8; 2];
    match tokio::time::timeout(REPLY_TAIL_TIMEOUT, stream.read_exact(&mut tail)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()),
    }
    let atyp = tail[1];
    match atyp {
        ATYP_IPV4 => {
            // Address (4 bytes) plus the optional bound port (2 bytes).
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            let _ = tokio::time::timeout(REPLY_PORT_TIMEOUT, stream.read_exact(&mut port)).await;
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            let _ = tokio::time::timeout(REPLY_PORT_TIMEOUT, stream.read_exact(&mut port)).await;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        other => {
            return Err(format!("raw-ip reply has an unknown ATYP: {other}").into());
        }
    }

    Ok(())
}

// -- Pumps ---------------------------------------------------------------

/// Wintun -> socket: forward every packet as a frame.
async fn pump_wintun_to_socket(
    wintun_rx: &mut Receiver<Vec<u8>>,
    writer: &mut (impl AsyncWrite + Unpin),
    stats: &RawIpStats,
    mtu: u16,
) -> std::io::Result<()> {
    while let Some(packet) = wintun_rx.recv().await {
        if packet.len() > mtu as usize {
            stats.dropped_oversize.fetch_add(1, Ordering::Relaxed);
            warn!(
                "rawip: dropping a {} byte packet - it exceeds the {mtu} byte MTU",
                packet.len()
            );
            continue;
        }
        let frame = encode_frame(&packet);
        if let Err(e) = writer.write_all(&frame).await {
            stats.io_errors.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "rawip: the socket write failed");
            return Err(e);
        }
        if let Err(e) = writer.flush().await {
            stats.io_errors.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "rawip: the socket flush failed");
            return Err(e);
        }
        stats.to_client.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Socket -> Wintun: read frames and inject the packets into the adapter.
async fn pump_socket_to_wintun(
    reader: &mut (impl AsyncRead + Unpin),
    wintun_tx: &Sender<Vec<u8>>,
    stats: &RawIpStats,
    mtu: u16,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    loop {
        let frame = match read_frame(reader, &mut buf, mtu).await {
            Ok(frame) => frame,
            Err(e) => {
                stats.io_errors.fetch_add(1, Ordering::Relaxed);
                warn!(error = %e, "rawip: the socket read failed");
                return Err(e);
            }
        };
        match frame {
            Some(Frame::Packet(packet)) => {
                stats.from_client.fetch_add(1, Ordering::Relaxed);
                if wintun_tx.send(packet).await.is_err() {
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    warn!("rawip: the wintun adapter refused the packet");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "wintun tx channel closed",
                    ));
                }
            }
            Some(Frame::TooLarge(len)) => {
                stats.dropped_oversize.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "rawip: dropping a {len} byte frame from the client - it exceeds the {mtu} byte MTU"
                );
            }
            Some(Frame::Empty) => {
                stats.malformed.fetch_add(1, Ordering::Relaxed);
                warn!("rawip: dropping an empty frame from the client");
            }
            None => return Ok(()),
        }
    }
}

/// Read one frame from the socket.
///
/// `buf` holds the bytes that were read from the socket but not consumed
/// yet; the leftovers stay in it for the next call.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    mtu: u16,
) -> std::io::Result<Option<Frame>> {
    let mut chunk = [0u8; 4096];
    loop {
        match decode_frame(buf, mtu) {
            Ok((frame, consumed)) => {
                buf.drain(..consumed);
                return Ok(Some(frame));
            }
            Err(FrameError::TooLarge { len, .. }) => {
                // The body is larger than the MTU.  Drop it, but keep the
                // stream in sync by consuming the whole frame.
                let frame_len = 2 + len as usize;
                while buf.len() < frame_len {
                    let n = reader.read(&mut chunk).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated oversized frame",
                        ));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                buf.drain(..frame_len);
                return Ok(Some(Frame::TooLarge(len)));
            }
            Err(FrameError::Truncated { .. }) => {
                let n = reader.read(&mut chunk).await?;
                if n == 0 {
                    if buf.is_empty() {
                        // Clean end of stream.
                        return Ok(None);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated frame",
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

// -- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::ChainEntry;

    fn chain(name: &str, addr: &str, protocol: ChainProtocol) -> ResolvedChain {
        ResolvedChain {
            entry: ChainEntry {
                chain_id: name.to_owned(),
                socks5_addr: addr.parse().expect("static addr is valid"),
                dns_upstream: None,
            },
            protocol,
        }
    }

    #[test]
    fn frame_round_trip() {
        let packet = vec![0x45u8; 64];
        let frame = encode_frame(&packet);
        assert_eq!(frame.len(), 2 + packet.len());
        assert_eq!(&frame[..2], &[0x00, 0x40]);

        let (decoded, consumed) = decode_frame(&frame, 1500).expect("frame decodes");
        assert_eq!(decoded, Frame::Packet(packet.clone()));
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn frame_round_trip_keeps_leftovers() {
        let packet = vec![0x11u8; 10];
        let mut stream = encode_frame(&packet);
        stream.extend_from_slice(&encode_frame(&[0x22u8; 10]));

        let (first, consumed) = decode_frame(&stream, 1500).expect("first frame decodes");
        assert_eq!(first, Frame::Packet(packet));
        let (second, _) = decode_frame(&stream[consumed..], 1500).expect("second frame decodes");
        assert_eq!(second, Frame::Packet(vec![0x22u8; 10]));
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let frame = encode_frame(&[0x45u8; 10]);
        let err = decode_frame(&frame[..frame.len() - 1], 1500).expect_err("truncated frame fails");
        assert_eq!(
            err,
            FrameError::Truncated {
                needed: 12,
                have: 11
            }
        );
    }

    #[test]
    fn header_only_frame_is_truncated() {
        let err = decode_frame(&[0x00, 0x10], 1500).expect_err("truncated frame fails");
        assert_eq!(err, FrameError::Truncated { needed: 18, have: 2 });
    }

    #[test]
    fn frame_over_mtu_is_rejected() {
        let packet = vec![0u8; 2000];
        let frame = encode_frame(&packet);
        let err = decode_frame(&frame, 1500).expect_err("oversized frame fails");
        assert_eq!(err, FrameError::TooLarge { len: 2000, limit: 1500 });
    }

    #[test]
    fn frame_at_mtu_is_accepted() {
        let packet = vec![0u8; 1500];
        let frame = encode_frame(&packet);
        let (decoded, consumed) = decode_frame(&frame, 1500).expect("frame decodes");
        assert_eq!(decoded, Frame::Packet(packet));
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn empty_frame_is_flagged() {
        let (decoded, consumed) = decode_frame(&[0x00, 0x00], 1500).expect("frame decodes");
        assert_eq!(decoded, Frame::Empty);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn raw_ip_chain_wins_over_socks5() {
        let chains = vec![
            chain("socks", "127.0.0.1:1080", ChainProtocol::Socks5),
            chain("raw", "127.0.0.1:1081", ChainProtocol::RawIp),
            chain("other", "127.0.0.1:1082", ChainProtocol::RawIp),
        ];
        let selected = select_raw_chain(&chains).expect("a chain is selected");
        assert_eq!(selected.entry.chain_id, "raw");
    }

    #[test]
    fn selection_falls_back_to_the_first_chain() {
        let chains = vec![
            chain("first", "127.0.0.1:1080", ChainProtocol::Socks5),
            chain("second", "127.0.0.1:1081", ChainProtocol::Socks5),
        ];
        let selected = select_raw_chain(&chains).expect("a chain is selected");
        assert_eq!(selected.entry.chain_id, "first");
    }

    #[test]
    fn selection_without_chains_is_none() {
        assert!(select_raw_chain(&[]).is_none());
    }
}
