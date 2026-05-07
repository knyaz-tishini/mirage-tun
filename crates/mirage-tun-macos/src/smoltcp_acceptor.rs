/// Wrappers around mirage-tcpip-stack types that implement the mirage-tun-core traits.
///
/// TCP forwarding is self-contained in the spawned tcp_accept_loop task in stack.rs.
/// SmoltcpTcpAcceptor is a noop stub that satisfies the StackHandle type constraint.
///
/// SmoltcpUdpSocket wraps the smoltcp UdpSocket (split into read/write halves).
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::udp::{ReadHalf, WriteHalf};
use mirage_tun_core::{error::TunError, traits};
use std::net::SocketAddr;
use tokio::net::TcpStream;

// ── SmoltcpTcpAcceptor ────────────────────────────────────────────────────────

/// No-op TcpAcceptor. Forwarding is done inside the spawned tcp_accept_loop.
pub struct SmoltcpTcpAcceptor {
    _priv: (),
}

impl SmoltcpTcpAcceptor {
    pub fn noop() -> Self {
        SmoltcpTcpAcceptor { _priv: () }
    }
}

#[async_trait]
impl traits::TcpAcceptor for SmoltcpTcpAcceptor {
    async fn accept(&mut self) -> Option<(TcpStream, SocketAddr, SocketAddr)> {
        // Never yields — TCP forwarding is handled by the dedicated spawn in stack.rs.
        std::future::pending().await
    }
}

// ── SmoltcpUdpSocket ──────────────────────────────────────────────────────────

pub struct SmoltcpUdpSocket {
    read: Option<ReadHalf>,
    write: Option<WriteHalf>,
}

impl SmoltcpUdpSocket {
    pub fn new(inner: mirage_tcpip_stack::UdpSocket) -> Self {
        let (read, write) = inner.split();
        Self { read: Some(read), write: Some(write) }
    }

    /// Returns a placeholder that never yields — used when the UDP socket is
    /// consumed by a self-contained forward loop spawned in stack.rs.
    pub fn noop() -> Self {
        Self { read: None, write: None }
    }
}

#[async_trait]
impl traits::UdpSocket for SmoltcpUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        match self.read.as_mut() {
            Some(r) => r.next().await,
            None => std::future::pending().await,
        }
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        match self.write.as_mut() {
            Some(w) => w.send((payload, src, dst)).await.map_err(TunError::Io),
            None => Ok(()),
        }
    }
}
