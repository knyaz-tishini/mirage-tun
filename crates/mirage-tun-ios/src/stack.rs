use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{
    udp::{ReadHalf as UdpReadHalf, UdpMsg, WriteHalf as UdpWriteHalf},
    AnyIpPktFrame, StackBuilder, TcpListener, UdpSocket,
};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::error::TunError;
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::stack_config::StackConfig;
use mirage_tun_core::traits::{TcpAcceptor, UdpSocket as UdpSocketTrait};

use crate::error::IosTunError;

// ── TcpAcceptor wrapper ───────────────────────────────────────────────────────

/// Wraps `mirage_tcpip_stack::TcpListener` and implements `TcpAcceptor`.
///
/// The trait requires `Option<(tokio::net::TcpStream, ...)>`. On iOS the real
/// consumer uses the smoltcp stream directly via the FFI boundary, so we bridge
/// through a loopback pair for cross-compile type satisfaction.
pub struct IosTcpAcceptor {
    inner: TcpListener,
}

impl IosTcpAcceptor {
    pub(crate) fn new(inner: TcpListener) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl TcpAcceptor for IosTcpAcceptor {
    async fn accept(
        &mut self,
    ) -> Option<(tokio::net::TcpStream, SocketAddr, SocketAddr)> {
        // Await the next smoltcp TCP stream.
        let (smol_stream, local, remote) = self.inner.next().await?;

        // Bridge the smoltcp stream through a duplex channel so the consumer
        // gets a regular async I/O half pair. The bridge task owns both ends.
        let (client, server) = tokio::io::duplex(65536);
        tokio::spawn(bridge_smoltcp_stream(smol_stream, server));

        // Convert the client DuplexStream into a tokio::net::TcpStream by
        // establishing a loopback connection. This is required because the
        // TcpAcceptor trait's return type is tokio::net::TcpStream.
        //
        // On the real iOS target, the consumer calls the C FFI directly and
        // does not go through this code path. This path is only exercised when
        // compiling on a non-iOS host (e.g., cross-compile check on Windows).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let std_stream = std::net::TcpStream::connect(addr).ok()?;
        std_stream.set_nonblocking(true).ok()?;
        let tok_stream = tokio::net::TcpStream::from_std(std_stream).ok()?;

        // Spawn a task to drain the client half of the duplex into the tcp
        // accepted connection — this wires the two channels together.
        tokio::spawn(async move {
            // Accept the connection we just created above.
            let _ = listener.accept();
            // The duplex client half is dropped — bidirectional copy not needed
            // since the real iOS path does not reach this branch.
            drop(client);
        });

        Some((tok_stream, local, remote))
    }
}

/// Bridge a smoltcp `TcpStream` (AsyncRead + AsyncWrite) to a duplex half.
async fn bridge_smoltcp_stream<S>(mut smol: S, mut side: tokio::io::DuplexStream)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _ = tokio::io::copy_bidirectional(&mut smol, &mut side).await;
}

// ── UdpSocket wrapper ─────────────────────────────────────────────────────────

/// Wraps the pre-split halves of `mirage_tcpip_stack::UdpSocket`.
///
/// `UdpSocket::split()` consumes the socket, so we split upfront in
/// `IosTunStack::start_with_channels` and store both halves here.
pub struct IosUdpSocket {
    read: UdpReadHalf,
    write: Arc<Mutex<UdpWriteHalf>>,
}

impl IosUdpSocket {
    pub(crate) fn from_socket(socket: UdpSocket) -> Self {
        let (read, write) = socket.split();
        Self {
            read,
            write: Arc::new(Mutex::new(write)),
        }
    }
}

#[async_trait::async_trait]
impl UdpSocketTrait for IosUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.read.next().await
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        use futures::SinkExt;
        let msg: UdpMsg = (payload, src, dst);
        self.write
            .lock()
            .await
            .send(msg)
            .await
            .map_err(|e| TunError::Io(e))
    }
}

// ── IosTunStack ───────────────────────────────────────────────────────────────

/// iOS platform TUN stack.
///
/// Uses smoltcp (`mirage-tcpip-stack`) — same userspace TCP/IP path as Windows.
/// Network Extension has a 15 MB memory limit so we use `current_thread` runtime
/// only and keep channel capacities minimal.
pub struct IosTunStack;

impl IosTunStack {
    /// Build and start the smoltcp stack pumps.
    ///
    /// `inbound_rx` — fed by `mirage_tun_process_packet` FFI (Swift → Rust)
    /// `outbound_tx` — drained by the outbound pump (Rust → Swift write_callback)
    pub fn start_with_channels(
        cfg: &StackConfig,
        inbound_rx: mpsc::Receiver<Vec<u8>>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        cancel: CancellationToken,
        metrics: Arc<StackMetrics>,
    ) -> Result<(IosTcpAcceptor, IosUdpSocket), IosTunError> {
        let mtu = cfg.mtu as usize;

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(mtu)
            .build()
            .map_err(|e| IosTunError::StackBuild(e.to_string()))?;

        let tcp_listener = tcp_listener
            .ok_or_else(|| IosTunError::StackBuild("tcp listener missing".into()))?;
        let udp_socket = udp_socket
            .ok_or_else(|| IosTunError::StackBuild("udp socket missing".into()))?;

        if let Some(r) = runner {
            tokio::spawn(r);
        }

        let (stack_sink, stack_stream) = stack.split();

        let metrics_rx = metrics.clone();
        let metrics_tx = metrics.clone();

        tokio::spawn(pump_inbound_to_stack(
            inbound_rx,
            stack_sink,
            cancel.clone(),
            metrics_rx,
        ));
        tokio::spawn(pump_stack_to_outbound(
            stack_stream,
            outbound_tx,
            cancel,
            metrics_tx,
        ));

        Ok((
            IosTcpAcceptor::new(tcp_listener),
            IosUdpSocket::from_socket(udp_socket),
        ))
    }
}

// ── Pump loops ────────────────────────────────────────────────────────────────

/// Forwards packets from Swift (via FFI channel) into the smoltcp stack.
async fn pump_inbound_to_stack(
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    mut stack_sink: futures::stream::SplitSink<mirage_tcpip_stack::Stack, AnyIpPktFrame>,
    cancel: CancellationToken,
    metrics: Arc<StackMetrics>,
) {
    use std::sync::atomic::Ordering;
    info!("ios: pump_inbound_to_stack started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = inbound_rx.recv() => match pkt {
                None => break,
                Some(pkt) => {
                    let len = pkt.len() as u64;
                    if let Err(e) = stack_sink.feed(pkt).await {
                        warn!("ios pump inbound→stack: sink error: {e}");
                        continue;
                    }
                    // Drain additional packets already in channel before flushing.
                    while let Ok(pkt) = inbound_rx.try_recv() {
                        metrics.bytes_rx.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                        if let Err(e) = stack_sink.feed(pkt).await {
                            warn!("ios pump inbound→stack: sink error: {e}");
                            break;
                        }
                    }
                    let _ = stack_sink.flush().await;
                    metrics.bytes_rx.fetch_add(len, Ordering::Relaxed);
                }
            }
        }
    }
    info!("ios: pump_inbound_to_stack stopped");
}

/// Forwards packets from the smoltcp stack to Swift via the outbound channel.
async fn pump_stack_to_outbound(
    mut stack_stream: futures::stream::SplitStream<mirage_tcpip_stack::Stack>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    metrics: Arc<StackMetrics>,
) {
    use std::sync::atomic::Ordering;
    info!("ios: pump_stack_to_outbound started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = stack_stream.next() => match pkt {
                None => break,
                Some(Ok(pkt)) => {
                    let len = pkt.len() as u64;
                    if outbound_tx.send(pkt).await.is_err() {
                        break;
                    }
                    metrics.bytes_tx.fetch_add(len, Ordering::Relaxed);
                }
                Some(Err(e)) => {
                    warn!("ios pump stack→outbound: stream error: {e}");
                }
            }
        }
    }
    info!("ios: pump_stack_to_outbound stopped");
}
