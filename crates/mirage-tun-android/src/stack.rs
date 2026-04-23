//! `AndroidTunStack` — `TunStack` impl using smoltcp (mirage-tcpip-stack).
//!
//! Android cannot use the kernel TCP/IP stack for userspace VPN traffic
//! (VpnService gives raw IP packets). smoltcp reassembles TCP streams and
//! UDP datagrams from those packets — the same path as Windows/wintun.
//!
//! # Thread safety
//! The smoltcp stack channels are `Send`. Tokio multi-thread runtime is used
//! so all futures must be `Send`.

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{AnyIpPktFrame, StackBuilder};
use mirage_tun_core::{
    metrics::StackMetrics,
    stack_config::StackConfig,
    traits::{private, StackHandle, TcpAcceptor, TunStack, UdpSocket},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::error::AndroidTunError;
use crate::vpn_service::AndroidTunDevice;

// ── TcpAcceptor wrapper ───────────────────────────────────────────────────────

/// Wraps the smoltcp `TcpListener` (which is a `Stream`) to impl `TcpAcceptor`.
pub struct AndroidTcpAcceptor {
    inner: mirage_tcpip_stack::TcpListener,
}

#[async_trait]
impl TcpAcceptor for AndroidTcpAcceptor {
    async fn accept(
        &mut self,
    ) -> Option<(tokio::net::TcpStream, SocketAddr, SocketAddr)> {
        // TcpListener is a Stream<Item = (TcpStream, SocketAddr, SocketAddr)>
        // but TcpStream here is mirage_tcpip_stack::TcpStream, not tokio::net::TcpStream.
        // The core trait requires tokio::net::TcpStream. We bridge via a loopback
        // pipe: smoltcp stream ↔ tokio duplex channel.
        let (stack_stream, local_addr, peer_addr) = self.inner.next().await?;
        // Build a tokio DuplexStream pair and splice the smoltcp stream into it.
        let (_client, server) = tokio::io::duplex(65536);
        tokio::spawn(splice_smoltcp_stream(stack_stream, server));
        // Bridge through a loopback TCP pair to produce a real tokio::net::TcpStream.
        Some(bridge_to_tcp_stream(_client, local_addr, peer_addr).await)
    }
}

/// Splice bytes between a smoltcp TcpStream and a tokio DuplexStream.
async fn splice_smoltcp_stream(
    mut smoltcp: mirage_tcpip_stack::TcpStream,
    mut duplex: tokio::io::DuplexStream,
) {
    use tokio::io::copy_bidirectional;
    if let Err(e) = copy_bidirectional(&mut smoltcp, &mut duplex).await {
        if e.kind() != std::io::ErrorKind::BrokenPipe
            && e.kind() != std::io::ErrorKind::ConnectionReset
        {
            error!("smoltcp splice error: {e}");
        }
    }
}

/// Bridge a `DuplexStream` to a `tokio::net::TcpStream` via an in-process
/// loopback connection.  Returns the remote-facing half as `TcpStream`.
async fn bridge_to_tcp_stream(
    duplex: tokio::io::DuplexStream,
    local_addr: SocketAddr,
    _peer_addr: SocketAddr,
) -> (tokio::net::TcpStream, SocketAddr, SocketAddr) {
    let bind_addr = if local_addr.is_ipv6() { "127.0.0.1:0" } else { "127.0.0.1:0" };
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("loopback listener bind");
    let relay_addr = listener
        .local_addr()
        .expect("loopback listener local_addr");

    let connect_fut = tokio::net::TcpStream::connect(relay_addr);
    let accept_fut = listener.accept();

    let (connect_result, accept_result) = tokio::join!(connect_fut, accept_fut);
    let connector = connect_result.expect("loopback connect");
    let (acceptor, acceptor_addr) = accept_result.expect("loopback accept");

    tokio::spawn(async move {
        use tokio::io::copy_bidirectional;
        let mut d = duplex;
        let mut c = connector;
        if let Err(e) = copy_bidirectional(&mut d, &mut c).await {
            if e.kind() != std::io::ErrorKind::BrokenPipe
                && e.kind() != std::io::ErrorKind::ConnectionReset
            {
                error!("duplex splice error: {e}");
            }
        }
    });

    (acceptor, relay_addr, acceptor_addr)
}

// ── UdpSocket wrapper ─────────────────────────────────────────────────────────

/// Wraps the smoltcp `UdpSocket` to impl `UdpSocket` core trait.
pub struct AndroidUdpSocket {
    read_half: mirage_tcpip_stack::udp::ReadHalf,
    write_half: mirage_tcpip_stack::udp::WriteHalf,
}

#[async_trait]
impl UdpSocket for AndroidUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.read_half.next().await
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), mirage_tun_core::error::TunError> {
        self.write_half
            .send((payload, src, dst))
            .await
            .map_err(mirage_tun_core::error::TunError::Io)
    }
}

// ── AndroidTunStack ───────────────────────────────────────────────────────────

/// Platform TUN stack for Android.
///
/// Receives a raw TUN fd from Kotlin's `VpnService.Builder.establish()`,
/// wraps it with smoltcp via `mirage-tcpip-stack`, and returns a
/// `StackHandle<AndroidTcpAcceptor, AndroidUdpSocket>`.
pub struct AndroidTunStack;

impl private::Sealed for AndroidTunStack {}

#[async_trait]
impl TunStack for AndroidTunStack {
    type Device = AndroidTunDevice;
    type Tcp = AndroidTcpAcceptor;
    type Udp = AndroidUdpSocket;
    type Error = AndroidTunError;

    async fn start(
        cfg: StackConfig,
        cancel: CancellationToken,
    ) -> Result<StackHandle<Self::Tcp, Self::Udp>, Self::Error> {
        // Retrieve pre-established fd from global state (set by jni_bridge).
        let fd = crate::jni_bridge::take_pending_fd()
            .ok_or_else(|| AndroidTunError::Other("no pending TUN fd".to_owned()))?;

        let mtu = cfg.mtu as usize;

        // Build smoltcp stack.
        let (stack, tcp_runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(false)
            .mtu(mtu)
            .build()
            .map_err(|e| AndroidTunError::SmoltcpBuild(e.to_string()))?;

        let tcp_listener = tcp_listener.expect("tcp enabled");
        let udp_socket = udp_socket.expect("udp enabled");

        if let Some(r) = tcp_runner {
            tokio::spawn(r);
        }

        let (stack_sink, stack_stream) = stack.split();

        // Channel: TUN read task → stack sink task.
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<AnyIpPktFrame>(1024);

        // Stack sink pump: receives raw IP frames from TUN and feeds smoltcp.
        let cancel_sink = cancel.clone();
        tokio::spawn(async move {
            let mut sink = stack_sink;
            loop {
                tokio::select! {
                    _ = cancel_sink.cancelled() => break,
                    pkt = inbound_rx.recv() => {
                        match pkt {
                            Some(frame) => {
                                if let Err(e) = sink.send(frame).await {
                                    error!("stack sink send: {e}");
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        // TUN read pump — reads raw IP packets from fd and forwards to smoltcp.
        let read_device = AndroidTunDevice::from_fd(fd)?;
        let cancel_read = cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 4];
            loop {
                tokio::select! {
                    _ = cancel_read.cancelled() => break,
                    result = read_device.recv(&mut buf) => {
                        match result {
                            Ok(n) if n > 0 => {
                                let frame: AnyIpPktFrame = buf[..n].to_vec();
                                if inbound_tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                    error!("TUN recv error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        // Channel: stack stream → TUN write pump.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<AnyIpPktFrame>(1024);

        // Stack stream pump: receives IP frames generated by smoltcp and queues for write.
        let cancel_stream = cancel.clone();
        tokio::spawn(async move {
            let mut stream = stack_stream;
            loop {
                tokio::select! {
                    _ = cancel_stream.cancelled() => break,
                    item = stream.next() => {
                        match item {
                            Some(Ok(frame)) => {
                                if outbound_tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            Some(Err(e)) => {
                                error!("stack stream error: {e}");
                                break;
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        // TUN write pump — takes smoltcp-generated frames and injects into TUN fd.
        // A second wrapper around the same fd is safe: TUN read/write are independent.
        let write_device = AndroidTunDevice::from_fd(fd)?;
        let cancel_write = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_write.cancelled() => break,
                    frame = outbound_rx.recv() => {
                        match frame {
                            Some(f) => {
                                if let Err(e) = write_device.send(&f).await {
                                    if e.kind() != std::io::ErrorKind::WouldBlock {
                                        error!("TUN send error: {e}");
                                        break;
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        let (udp_read, udp_write) = udp_socket.split();
        let metrics = Arc::new(StackMetrics::default());

        Ok(StackHandle {
            tcp: AndroidTcpAcceptor {
                inner: tcp_listener,
            },
            udp: AndroidUdpSocket {
                read_half: udp_read,
                write_half: udp_write,
            },
            metrics,
        })
    }
}
