use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    task::{Context, Poll},
};

use mirage_ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::mpsc::{self, Receiver, Sender},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::wintun::{WintunReader, WintunWriter};
use crate::error::Result;

// ── PacketDevice ──────────────────────────────────────────────────────────────

struct PacketDevice {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
    pending_read: Option<(Vec<u8>, usize)>,
}

impl PacketDevice {
    fn new(rx: Receiver<Vec<u8>>, tx: Sender<Vec<u8>>) -> Self {
        Self { rx, tx, pending_read: None }
    }
}

impl AsyncRead for PacketDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if let Some((ref data, ref mut offset)) = this.pending_read {
            let remaining = &data[*offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            *offset += to_copy;
            if *offset >= data.len() {
                this.pending_read = None;
            }
            return Poll::Ready(Ok(()));
        }

        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let to_copy = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..to_copy]);
                if to_copy < packet.len() {
                    this.pending_read = Some((packet, to_copy));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "PacketDevice write channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── IpStackRunner ─────────────────────────────────────────────────────────────

/// Owns the background tasks that bridge Wintun ↔ IpStack ↔ SOCKS5.
pub struct IpStackRunner {
    cancel: CancellationToken,
}

impl IpStackRunner {
    pub async fn start(
        reader: WintunReader,
        writer: WintunWriter,
        socks5_addr: SocketAddr,
        cancel: CancellationToken,
    ) -> Result<Self> {
        info!("IpStackRunner: started, socks5={socks5_addr}");

        let (wintun_to_stack_tx, wintun_to_stack_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (stack_to_wintun_tx, mut stack_to_wintun_rx) = mpsc::channel::<Vec<u8>>(1024);

        let device = PacketDevice::new(wintun_to_stack_rx, stack_to_wintun_tx);

        // ── Wintun → stack reader task ────────────────────────────────────────
        let reader_cancel = cancel.clone();
        let reader_tx = wintun_to_stack_tx;
        tokio::spawn(async move {
            let mut pkt_count: u64 = 0;
            let mut timeout_count: u64 = 0;
            let start = std::time::Instant::now();
            loop {
                tokio::select! {
                    _ = reader_cancel.cancelled() => break,
                    result = reader.recv() => {
                        match result {
                            Ok(packet) if packet.is_empty() => {
                                timeout_count += 1;
                                if timeout_count <= 3 || timeout_count % 50 == 0 {
                                    info!("IpStackRunner: Wintun read timeout #{timeout_count}");
                                }
                                continue;
                            }
                            Ok(packet) => {
                                pkt_count += 1;
                                let elapsed = start.elapsed().as_secs();
                                if pkt_count <= 20 || pkt_count % 100 == 0 || (elapsed % 10 == 0 && pkt_count % 10 == 1) {
                                    let ip_ver = packet.first().map(|b| b >> 4).unwrap_or(0);
                                    let proto = if ip_ver == 4 && packet.len() >= 10 { packet[9] } else { 0 };
                                    info!(
                                        "IpStackRunner: pkt #{pkt_count} {} bytes IPv{ip_ver} proto={proto} (timeouts={timeout_count})",
                                        packet.len()
                                    );
                                }
                                if reader_tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("IpStackRunner: Wintun read error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // ── Stack → Wintun writer task ────────────────────────────────────────
        let writer_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut first_write = true;
            loop {
                tokio::select! {
                    _ = writer_cancel.cancelled() => break,
                    packet = stack_to_wintun_rx.recv() => {
                        match packet {
                            None => break,
                            Some(pkt) => {
                                if first_write {
                                    info!(
                                        "IpStackRunner: first packet written back to Wintun, {} bytes",
                                        pkt.len()
                                    );
                                    first_write = false;
                                }
                                if let Err(e) = writer.send(pkt).await {
                                    warn!("IpStackRunner: Wintun write error: {e}");
                                }
                            }
                        }
                    }
                }
            }
        });

        // ── IpStack accept loop ───────────────────────────────────────────────
        let mut config = IpStackConfig::default();
        config.mtu_unchecked(1500);

        let mut stack = IpStack::new(config, device);
        let accept_cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = accept_cancel.cancelled() => break,
                    result = stack.accept() => {
                        match result {
                            Err(e) => {
                                warn!("IpStackRunner: accept error: {e}");
                                break;
                            }
                            Ok(stream) => {
                                handle_stream(stream, socks5_addr, accept_cancel.clone());
                            }
                        }
                    }
                }
            }
        });

        Ok(Self { cancel })
    }
}

impl Drop for IpStackRunner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

// ── Stream handler ────────────────────────────────────────────────────────────

fn handle_stream(stream: IpStackStream, socks5_addr: SocketAddr, cancel: CancellationToken) {
    match stream {
        IpStackStream::Tcp(mut tcp) => {
            let dst = tcp.local_addr();
            info!("IpStackRunner: TCP → {dst}");
            tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    result = handle_tcp(&mut tcp, socks5_addr, dst) => {
                        if let Err(e) = result {
                            info!("IpStackRunner: TCP {dst} error: {e}");
                        }
                    }
                }
            });
        }
        IpStackStream::Udp(mut udp) => {
            let dst = udp.local_addr();
            if dst.port() == 53 {
                info!("IpStackRunner: UDP DNS → {dst}");
                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        result = handle_dns_udp(&mut udp) => {
                            if let Err(e) = result {
                                info!("IpStackRunner: DNS UDP error: {e}");
                            }
                        }
                    }
                });
            } else {
                info!("IpStackRunner: UDP → {dst} (non-DNS, dropped)");
            }
        }
        _ => {}
    }
}

// ── TCP → SOCKS5 ──────────────────────────────────────────────────────────────

async fn handle_tcp(
    tcp: &mut mirage_ipstack::IpStackTcpStream,
    socks5_addr: SocketAddr,
    dst: SocketAddr,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match socks5_connect(socks5_addr, dst).await {
        Ok(mut proxy) => {
            info!("IpStackRunner: SOCKS5 connected to {dst}");
            tokio::io::copy_bidirectional(tcp, &mut proxy).await?;
        }
        Err(e) => {
            warn!("IpStackRunner: SOCKS5 to {dst} failed: {e}");
            return Err(e);
        }
    }
    Ok(())
}

// ── DNS UDP forwarding ────────────────────────────────────────────────────────

async fn handle_dns_udp(
    udp: &mut mirage_ipstack::IpStackUdpStream,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::UdpSocket;

    let upstream: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
    let bind: SocketAddr = "0.0.0.0:0".parse()?;

    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;

    let mut buf = vec![0u8; 4096];
    let n = udp.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    sock.send(&buf[..n]).await?;

    let mut resp = vec![0u8; 4096];
    let m = sock.recv(&mut resp).await?;
    info!("IpStackRunner: DNS query {} bytes → 8.8.8.8, response {} bytes", n, m);
    udp.write_all(&resp[..m]).await?;

    Ok(())
}

// ── SOCKS5 no-auth connect ────────────────────────────────────────────────────

async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(proxy).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
        return Err(format!(
            "SOCKS5 greeting rejected: {:02x} {:02x}",
            greeting_resp[0], greeting_resp[1]
        )
        .into());
    }

    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    stream.write_all(&req).await?;

    let mut resp_hdr = [0u8; 4];
    stream.read_exact(&mut resp_hdr).await?;

    if resp_hdr[0] != 0x05 {
        return Err(format!("SOCKS5 bad version in response: {}", resp_hdr[0]).into());
    }
    if resp_hdr[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected, code: {}", resp_hdr[1]).into());
    }

    match resp_hdr[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut skip = vec![0u8; len + 2];
            stream.read_exact(&mut skip).await?;
        }
        atyp => {
            return Err(format!("SOCKS5 unknown ATYP in response: {atyp}").into());
        }
    }

    Ok(stream)
}
