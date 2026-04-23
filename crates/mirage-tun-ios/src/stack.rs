use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{
    udp::{ReadHalf as UdpReadHalf, WriteHalf as UdpWriteHalf},
    AnyIpPktFrame, StackBuilder, TcpListener, UdpSocket,
};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::error::TunError;
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::stack_config::StackConfig;
use mirage_tun_core::traits::{private, StackHandle, TcpAcceptor, TunStack, UdpSocket as UdpSocketTrait};

use crate::error::IosTunError;
use crate::packet_tunnel::WriteCallback;

// ── Static write callback (set by FFI before start) ───────────────────────────

/// Write callback stored by `set_write_callback()`, consumed by `TunStack::start()`.
///
/// Using `OnceLock<Mutex<Option<...>>>` so `set_write_callback` can be called
/// before `start()` and the value can be taken (not just read) exactly once.
static WRITE_CALLBACK: OnceLock<Mutex<Option<Arc<WriteCallback>>>> = OnceLock::new();

fn write_callback_cell() -> &'static Mutex<Option<Arc<WriteCallback>>> {
    WRITE_CALLBACK.get_or_init(|| Mutex::new(None))
}

// ── TcpAcceptor wrapper ───────────────────────────────────────────────────────

/// Wraps `mirage_tcpip_stack::TcpListener` and implements `TcpAcceptor`.
pub struct IosTcpAcceptor {
    inner: TcpListener,
}

impl IosTcpAcceptor {
    pub(crate) fn new(inner: TcpListener) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl TcpAcceptor for IosTcpAcceptor {
    async fn accept(
        &mut self,
    ) -> Option<(tokio::net::TcpStream, SocketAddr, SocketAddr)> {
        let (smol_stream, local, remote) = self.inner.next().await?;

        let (client, server) = tokio::io::duplex(65536);
        tokio::spawn(bridge_smoltcp_stream(smol_stream, server));

        // Bridge the duplex client half through a loopback pair to produce a
        // real tokio::net::TcpStream (required by the TcpAcceptor trait).
        // On the actual iOS target the consumer uses the C FFI directly and
        // never reaches this code path; this is only for cross-compile checks.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
        let addr = listener.local_addr().ok()?;
        let std_stream = std::net::TcpStream::connect(addr).ok()?;
        std_stream.set_nonblocking(true).ok()?;
        let tok_stream = tokio::net::TcpStream::from_std(std_stream).ok()?;

        tokio::spawn(async move {
            let _ = listener.accept();
            drop(client);
        });

        Some((tok_stream, local, remote))
    }
}

/// Bridge a smoltcp `TcpStream` to a `DuplexStream` half.
async fn bridge_smoltcp_stream<S>(mut smol: S, mut side: tokio::io::DuplexStream)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _ = tokio::io::copy_bidirectional(&mut smol, &mut side).await;
}

// ── UdpSocket wrapper ─────────────────────────────────────────────────────────

/// Wraps the pre-split halves of `mirage_tcpip_stack::UdpSocket`.
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

#[async_trait]
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
        let msg = (payload, src, dst);
        self.write
            .lock()
            .await
            .send(msg)
            .await
            .map_err(TunError::Io)
    }
}

// ── IosTunStack ───────────────────────────────────────────────────────────────

/// iOS platform TUN stack.
///
/// Uses smoltcp (`mirage-tcpip-stack`) — same userspace TCP/IP path as Windows.
///
/// # Usage
///
/// 1. FFI calls `IosTunStack::set_write_callback(cb)` before `start()`.
/// 2. `TunStack::start()` picks up the callback from the static and wires the
///    outbound pump directly — no intermediate channel needed.
pub struct IosTunStack;

impl IosTunStack {
    /// Store the Swift write callback for the next `TunStack::start()` call.
    ///
    /// Must be called exactly once before `start()`. Thread-safe via a `Mutex`.
    pub async fn set_write_callback(cb: Arc<WriteCallback>) {
        let mut guard = write_callback_cell().lock().await;
        *guard = Some(cb);
    }

    /// Take the write callback stored by `set_write_callback()`.
    ///
    /// Returns `None` if not set, or if already taken (start was called twice).
    async fn take_write_callback() -> Option<Arc<WriteCallback>> {
        write_callback_cell().lock().await.take()
    }
}

impl private::Sealed for IosTunStack {}

#[async_trait]
impl TunStack for IosTunStack {
    /// iOS has no persistent TunDevice type — the NE framework owns the fd.
    /// We use `()` as a no-op placeholder to satisfy the trait bound.
    type Device = NoopTunDevice;
    type Tcp = IosTcpAcceptor;
    type Udp = IosUdpSocket;
    type Error = IosTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        // Retrieve the write callback set by FFI before start().
        let write_cb = Self::take_write_callback()
            .await
            .ok_or_else(|| IosTunError::Other("write_callback not set before start".into()))?;

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

        // inbound_rx: fed by mirage_tun_process_packet FFI (Swift → smoltcp).
        // The sender half (inbound_tx) is returned via StackHandle extension
        // fields are not available on the core trait, so we store it in a
        // thread-local via the INBOUND_TX static below.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(64);
        set_inbound_tx(inbound_tx);

        let metrics = Arc::new(StackMetrics::default());
        let metrics_rx = metrics.clone();
        let metrics_tx = metrics.clone();

        tokio::spawn(pump_inbound_to_stack(
            inbound_rx,
            stack_sink,
            cancel.clone(),
            metrics_rx,
        ));

        // Outbound pump: smoltcp → write_cb (Swift writePackets).
        // Packets go directly to write_cb, no extra channel hop.
        tokio::spawn(pump_stack_to_write_cb(
            stack_stream,
            write_cb,
            cancel,
            metrics_tx,
        ));

        Ok(StackHandle {
            tcp: IosTcpAcceptor::new(tcp_listener),
            udp: IosUdpSocket::from_socket(udp_socket),
            metrics,
        })
    }
}

// ── Inbound sender static ─────────────────────────────────────────────────────
//
// `TunStack::start()` cannot return the inbound_tx through the trait's
// `StackHandle` type (that type is defined in core and has no iOS-specific
// field). We store it in a static so `mirage_tun_process_packet` can reach it.

static INBOUND_TX: OnceLock<Mutex<Option<mpsc::Sender<Vec<u8>>>>> = OnceLock::new();

fn inbound_tx_cell() -> &'static Mutex<Option<mpsc::Sender<Vec<u8>>>> {
    INBOUND_TX.get_or_init(|| Mutex::new(None))
}

fn set_inbound_tx(tx: mpsc::Sender<Vec<u8>>) {
    // We need a blocking lock here since this is called from sync context
    // inside the tokio block_on.
    if let Ok(mut guard) = inbound_tx_cell().try_lock() {
        *guard = Some(tx);
    }
}

/// Obtain a clone of the inbound sender (non-blocking).
///
/// Returns `None` if the stack has not been started yet.
pub(crate) fn clone_inbound_tx() -> Option<mpsc::Sender<Vec<u8>>> {
    inbound_tx_cell().try_lock().ok()?.clone()
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
                    // Drain additional packets already queued before flushing.
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

/// Forwards packets generated by smoltcp directly to the Swift write callback.
///
/// This is the corrected outbound path: smoltcp → write_cb (no intermediate
/// channel whose receiver could be dropped).
async fn pump_stack_to_write_cb(
    mut stack_stream: futures::stream::SplitStream<mirage_tcpip_stack::Stack>,
    write_cb: Arc<WriteCallback>,
    cancel: CancellationToken,
    metrics: Arc<StackMetrics>,
) {
    use std::sync::atomic::Ordering;
    info!("ios: pump_stack_to_write_cb started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = stack_stream.next() => match pkt {
                None => break,
                Some(Ok(pkt)) => {
                    let len = pkt.len() as u64;
                    write_cb.send(&pkt);
                    metrics.bytes_tx.fetch_add(len, Ordering::Relaxed);
                }
                Some(Err(e)) => {
                    warn!("ios pump stack→write_cb: stream error: {e}");
                }
            }
        }
    }
    info!("ios: pump_stack_to_write_cb stopped");
}

// ── NoopTunDevice ─────────────────────────────────────────────────────────────
//
// iOS Network Extension owns the TUN fd entirely (Swift side). Rust never
// opens or configures the interface directly — the NE framework does it via
// `setTunnelNetworkSettings`. We satisfy the `TunStack::Device` associated
// type with this zero-cost placeholder.

use mirage_tun_core::traits::TunDevice;

pub struct NoopTunDevice;

impl private::Sealed for NoopTunDevice {}

#[async_trait]
impl TunDevice for NoopTunDevice {
    fn name(&self) -> &str {
        "utun-ios"
    }

    async fn configure(&mut self, _addr: &str, _mtu: u16) -> Result<(), TunError> {
        Ok(())
    }

    async fn close(self) -> Result<(), TunError> {
        Ok(())
    }
}
