use std::net::SocketAddr;
use async_trait::async_trait;
use futures::StreamExt;
use mirage_tcpip_stack::TcpListener;
use mirage_tun_core::traits::TcpAcceptor;
use tokio::net::TcpStream;
use tracing::warn;

/// TcpAcceptor backed by mirage-tcpip-stack's TcpListener.
///
/// The core trait requires `tokio::net::TcpStream` (a real OS socket), but
/// the smoltcp backend produces virtual `mirage_tcpip_stack::TcpStream` objects.
/// We bridge the two via a localhost loopback TCP pair: one side is pumped from
/// the smoltcp stream; the other is returned as a real `tokio::net::TcpStream`.
pub struct WintunTcpAcceptor {
    inner: TcpListener,
}

impl WintunTcpAcceptor {
    pub fn new(inner: TcpListener) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl TcpAcceptor for WintunTcpAcceptor {
    async fn accept(&mut self) -> Option<(TcpStream, SocketAddr, SocketAddr)> {
        let (smol_stream, local_addr, peer_addr) = self.inner.next().await?;

        // Bind a loopback listener on a random port.
        let bridge_listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                warn!("WintunTcpAcceptor: loopback bind failed: {e}");
                return None;
            }
        };
        let bridge_addr = match bridge_listener.local_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!("WintunTcpAcceptor: local_addr failed: {e}");
                return None;
            }
        };

        // Spawn the bridge server — accepts one connection and pumps data.
        tokio::spawn(async move {
            match bridge_listener.accept().await {
                Ok((mut server_conn, _)) => {
                    let mut smol = smol_stream;
                    let _ = tokio::io::copy_bidirectional(&mut smol, &mut server_conn).await;
                }
                Err(e) => {
                    warn!("WintunTcpAcceptor: bridge accept failed: {e}");
                }
            }
        });

        // Return the client side as a real tokio::net::TcpStream.
        match TcpStream::connect(bridge_addr).await {
            Ok(stream) => Some((stream, local_addr, peer_addr)),
            Err(e) => {
                warn!("WintunTcpAcceptor: bridge connect failed: {e}");
                None
            }
        }
    }
}
