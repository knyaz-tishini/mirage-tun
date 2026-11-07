use std::net::SocketAddr;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::udp::{ReadHalf, WriteHalf};
use mirage_tun_core::{error::TunError, traits::UdpSocket};

/// UdpSocket backed by the mirage-tcpip-stack's split UDP halves.
///
/// The smoltcp UDP socket is split at construction time into (ReadHalf, WriteHalf).
/// `recv()` polls the ReadHalf stream; `send()` pushes into the WriteHalf sink.
pub struct WintunUdpSocket {
    read: ReadHalf,
    write: WriteHalf,
}

impl WintunUdpSocket {
    pub fn new(inner: mirage_tcpip_stack::UdpSocket) -> Self {
        let (read, write) = inner.split();
        Self { read, write }
    }
}

#[async_trait]
impl UdpSocket for WintunUdpSocket {
    async fn recv(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.read.next().await
    }

    async fn send(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), TunError> {
        self.write
            .send((payload, src, dst))
            .await
            .map_err(TunError::Io)
    }
}
