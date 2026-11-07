use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use futures::Stream;
use crate::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, TcpPacket},
};
use std::sync::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Notify,
    },
};
use tracing::{error, trace, warn};

/// Capacity of the wintun→smoltcp ingress packet channel.
pub const INGRESS_CHANNEL_SIZE: usize = 4096;
/// Capacity of the newly-accepted TcpStream channel.
pub const STREAM_CHANNEL_SIZE: usize = 1024;
/// Capacity of the internal socket-creation event channel.
pub const SOCKET_EVENT_CHANNEL_SIZE: usize = 1024;

/// Monotonically-incrementing drop counters shared between the packet handler
/// and the periodic logger task.
pub(crate) struct DropCounters {
    pub dropped_ingress: AtomicU64,
    pub dropped_streams: AtomicU64,
    pub dropped_socket_events: AtomicU64,
}

impl DropCounters {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            dropped_ingress: AtomicU64::new(0),
            dropped_streams: AtomicU64::new(0),
            dropped_socket_events: AtomicU64::new(0),
        })
    }
}

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

/// Default TCP socket-level send/recv buffer — 512 KB.
/// Used by `TcpListener::new` unless overridden via `send_buffer_size`/`recv_buffer_size`.
pub const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 0x3FFF * 8; // ~524 KB
/// Default TCP socket-level recv buffer — 512 KB.
pub const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 0x3FFF * 8; // ~524 KB

/// Established sockets with no send/recv activity for this long are aborted.
/// Covers peers that vanish without sending FIN (e.g. mobile handoff, NAT expiry).
pub const IDLE_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Half-closed sockets (CloseWait / FinWait2 / Closing / LastAck / TimeWait)
/// that linger for this long are aborted.  These should complete quickly;
/// a 60-second cap prevents buffer-leaks when the peer disappears mid-teardown.
pub const HALF_CLOSED_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Minimum age a socket must reach before the idle-reaper considers it.
/// Prevents aborting brand-new connections that haven't yet exchanged the
/// first byte (SYN-RECEIVED → ESTABLISHED transition takes a round trip).
const REAPER_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
    /// Wall-clock instant of the last successful send or recv on this socket.
    /// Updated by the `handle_socket` loop whenever bytes flow.  Used by the
    /// idle-reaper to decide when to abort stale connections.
    last_active: std::time::Instant,
    /// Wall-clock instant when this socket was created (SYN received).
    /// The reaper ignores sockets younger than `REAPER_GRACE_PERIOD` so that
    /// connections that haven't exchanged the first byte yet are not killed.
    creation_time: std::time::Instant,
}

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;

fn lock_control(m: &SpinMutex<TcpSocketControl>) -> std::sync::MutexGuard<'_, TcpSocketControl> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct TcpListenerRunner;

impl TcpListenerRunner {
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: Sender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: Sender<TcpStream>,
        sockets: HashMap<SocketHandle, SharedControl>,
        send_buffer_size: u32,
        recv_buffer_size: u32,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (socket_tx, socket_rx) = channel::<TcpSocketCreation>(SOCKET_EVENT_CHANNEL_SIZE);
            let counters = DropCounters::new();

            // Periodic logger: every 60 s emit a warn! if any drops occurred.
            let log_counters = counters.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                // Skip the immediate tick so we don't log at t=0.
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let ingress = log_counters.dropped_ingress.swap(0, Ordering::Relaxed);
                    let streams = log_counters.dropped_streams.swap(0, Ordering::Relaxed);
                    let sock_ev = log_counters.dropped_socket_events.swap(0, Ordering::Relaxed);
                    if ingress > 0 || streams > 0 || sock_ev > 0 {
                        warn!(
                            "tcpip-stack channel drops (last 60s): ingress={} streams={} socket_events={}",
                            ingress, streams, sock_ev
                        );
                    }
                }
            });

            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, send_buffer_size, recv_buffer_size, counters) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, socket_rx) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: Sender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: Sender<TcpStream>,
        socket_tx: Sender<TcpSocketCreation>,
        send_buffer_size: u32,
        recv_buffer_size: u32,
        counters: Arc<DropCounters>,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            Self::process_one_frame(
                &notify,
                &iface_ingress_tx,
                &iface_ingress_tx_avail,
                &stream_tx,
                &socket_tx,
                frame,
                send_buffer_size,
                recv_buffer_size,
                &counters,
            )?;

            // Drain any additional packets already in the channel —
            // batch them so handle_socket sees all of them in one poll.
            while let Ok(frame) = tcp_rx.try_recv() {
                Self::process_one_frame(
                    &notify,
                    &iface_ingress_tx,
                    &iface_ingress_tx_avail,
                    &stream_tx,
                    &socket_tx,
                    frame,
                    send_buffer_size,
                    recv_buffer_size,
                    &counters,
                )?;
            }
        }
        Ok(())
    }

    fn process_one_frame(
        notify: &SharedNotify,
        iface_ingress_tx: &Sender<Vec<u8>>,
        iface_ingress_tx_avail: &Arc<AtomicBool>,
        stream_tx: &Sender<TcpStream>,
        socket_tx: &Sender<TcpSocketCreation>,
        frame: AnyIpPktFrame,
        send_buffer_size: u32,
        recv_buffer_size: u32,
        counters: &DropCounters,
    ) -> std::io::Result<()> {
        let packet = match IpPacket::new_checked(frame.as_slice()) {
            Ok(p) => p,
            Err(err) => {
                error!("invalid TCP IP packet: {:?}", err);
                return Ok(());
            }
        };

        // Specially handle icmp packet by TCP interface.
        if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
            match iface_ingress_tx.try_send(frame) {
                Ok(_) => {
                    iface_ingress_tx_avail.store(true, Ordering::Release);
                    notify.notify_one();
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    counters.dropped_ingress.fetch_add(1, Ordering::Relaxed);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "iface_ingress_tx closed",
                    ));
                }
            }
            return Ok(());
        }

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();
        let payload = packet.payload();

        let packet = match TcpPacket::new_checked(payload) {
            Ok(p) => p,
            Err(err) => {
                error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                return Ok(());
            }
        };
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();

        let src_addr = SocketAddr::new(src_ip, src_port);
        let dst_addr = SocketAddr::new(dst_ip, dst_port);

        // TCP first handshake packet, create a new Connection
        if packet.syn() && !packet.ack() {
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; recv_buffer_size as usize]),
                TcpSocketBuffer::new(vec![0u8; send_buffer_size as usize]),
            );
            socket.set_keep_alive(Some(Duration::from_secs(28)));
            socket.set_timeout(Some(Duration::from_secs(7200)));
            socket.set_ack_delay(None);
            socket.set_nagle_enabled(false);

            if let Err(err) = socket.listen(dst_addr) {
                error!("listen error: {:?}", err);
                return Ok(());
            }

            trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

            let now = std::time::Instant::now();
            let control = Arc::new(SpinMutex::new(TcpSocketControl {
                send_buffer: RingBuffer::new(vec![0u8; send_buffer_size as usize]),
                send_waker: None,
                recv_buffer: RingBuffer::new(vec![0u8; recv_buffer_size as usize]),
                recv_waker: None,
                recv_state: TcpSocketState::Normal,
                send_state: TcpSocketState::Normal,
                last_active: now,
                creation_time: now,
            }));

            let stream = TcpStream {
                src_addr,
                dst_addr,
                notify: notify.clone(),
                control: control.clone(),
            };
            match stream_tx.try_send(stream) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Consumer is not keeping up — drop this incoming connection.
                    // The SYN packet is still forwarded to smoltcp below, but
                    // no TcpStream reaches the consumer; smoltcp will RST it
                    // naturally when the socket is never polled.
                    counters.dropped_streams.fetch_add(1, Ordering::Relaxed);
                    // Still pipeline the SYN frame so smoltcp can RST cleanly.
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "stream_tx closed",
                    ));
                }
            }

            match socket_tx.try_send(TcpSocketCreation { control, socket }) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    counters.dropped_socket_events.fetch_add(1, Ordering::Relaxed);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "socket_tx closed",
                    ));
                }
            }
        }

        // Pipeline tcp stream packet
        match iface_ingress_tx.try_send(frame) {
            Ok(_) => {
                iface_ingress_tx_avail.store(true, Ordering::Release);
                notify.notify_one();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                counters.dropped_ingress.fetch_add(1, Ordering::Relaxed);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "iface_ingress_tx closed",
                ));
            }
        }
        Ok(())
    }

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, SharedControl>,
        mut socket_rx: Receiver<TcpSocketCreation>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        loop {
            while let Ok(TcpSocketCreation { control, socket }) = socket_rx.try_recv() {
                let handle = socket_set.add(socket);
                sockets.insert(handle, control);
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                crate::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();

            for (socket_handle, control) in sockets.iter() {
                let socket_handle = *socket_handle;
                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = lock_control(&control);

                // Remove the socket only when it is in the closed state.
                if socket.state() == TcpState::Closed {
                    sockets_to_remove.push(socket_handle);

                    control.send_state = TcpSocketState::Closed;
                    control.recv_state = TcpSocketState::Closed;

                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }

                    trace!("closed TCP connection");
                    continue;
                }

                // SHUT_WR — only close once the send_buffer has been fully
                // drained into the smoltcp socket.  Closing earlier transitions
                // the socket to FIN_WAIT_1, making can_send() return false, so
                // the send loop below never runs and the remaining data is lost.
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                {
                    trace!("closing TCP Write Half, {:?}", socket.state());

                    socket.close();
                    control.send_state = TcpSocketState::Closing;
                }

                // Check if readable
                let mut wake_receiver = false;
                while socket.can_recv() && !control.recv_buffer.is_full() {
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => {
                            wake_receiver = true;
                            control.last_active = std::time::Instant::now();
                        }
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => {
                            wake_sender = true;
                            control.last_active = std::time::Instant::now();
                        }
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            for socket_handle in sockets_to_remove {
                sockets.remove(&socket_handle);
                socket_set.remove(socket_handle);
            }

            // ── Idle-socket reaper ────────────────────────────────────────────
            // Walk all live sockets and abort those that have been silent too
            // long.  Two thresholds:
            //   • IDLE_KILL_TIMEOUT     — fully Established, no bytes flowing
            //   • HALF_CLOSED_KILL_TIMEOUT — lingering teardown states
            //
            // Sockets younger than REAPER_GRACE_PERIOD are always skipped so
            // that brand-new connections completing their SYN/SYN-ACK handshake
            // are not killed before the first byte arrives.
            {
                let reaper_now = std::time::Instant::now();
                let mut reaper_abort = Vec::new();

                for (handle, control) in sockets.iter() {
                    let socket = socket_set.get_mut::<TcpSocket>(*handle);
                    let ctrl = lock_control(control);

                    // Skip sockets still in early establishment phases —
                    // they haven't had a chance to transfer data yet.
                    if reaper_now.duration_since(ctrl.creation_time) < REAPER_GRACE_PERIOD {
                        continue;
                    }

                    let idle = reaper_now.duration_since(ctrl.last_active);
                    let state = socket.state();

                    let should_abort = match state {
                        TcpState::Established => idle >= IDLE_KILL_TIMEOUT,
                        TcpState::CloseWait
                        | TcpState::FinWait2
                        | TcpState::Closing
                        | TcpState::LastAck
                        | TcpState::TimeWait => idle >= HALF_CLOSED_KILL_TIMEOUT,
                        // All other states (Listen, SynSent, SynReceived, FinWait1,
                        // Closed) are either transient or already handled elsewhere.
                        _ => false,
                    };

                    if should_abort {
                        let peer = socket.remote_endpoint();
                        reaper_abort.push((*handle, peer, state, idle));
                    }
                }

                for (handle, peer, state, idle) in reaper_abort {
                    warn!(
                        "idle-reaper: aborting {} socket peer={:?} idle={:.1}s",
                        state,
                        peer,
                        idle.as_secs_f64(),
                    );
                    let socket = socket_set.get_mut::<TcpSocket>(handle);
                    socket.abort();
                    // The next poll iteration will see state == Closed and
                    // enqueue the handle in sockets_to_remove normally.
                }
            }

            // If poll processed something, immediately loop again — there
            // may be generated packets (SYN-ACK, ACK) that need another
            // poll iteration to send.  Yield to let pump tasks run.
            if matches!(
                updated_sockets,
                crate::iface::PollResult::SocketStateChanged
            ) {
                tokio::task::yield_now().await;
                continue;
            }

            // Nothing happened.  Wait for notification of new packets or
            // data from TcpStream writers.  No timeout cap — notify fires
            // on every new ingress packet and every TcpStream write.
            if !iface_ingress_tx_avail.load(Ordering::Acquire) {
                let raw = iface
                    .poll_delay(before_poll, &socket_set)
                    .unwrap_or(Duration::from_millis(100));
                if raw != Duration::ZERO {
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from(raw),
                        notify.notified(),
                    )
                    .await;
                }
            }
        }
    }
}

pub struct TcpListener {
    stream_rx: Receiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
        send_buffer_size: u32,
        recv_buffer_size: u32,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) =
            VirtualDevice::new(stack_tx, mtu);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = channel(STREAM_CHANNEL_SIZE);

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            HashMap::new(),
            send_buffer_size,
            recv_buffer_size,
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = lock_control(&self.control);

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = lock_control(&self.control);

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = lock_control(&self.control);

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(std::io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = lock_control(&self.control);

        if matches!(control.send_state, TcpSocketState::Closed) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}
