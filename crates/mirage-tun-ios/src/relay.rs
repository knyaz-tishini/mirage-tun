//! Forward smoltcp TCP streams and UDP datagrams to the in-process SOCKS5 listener.
//!
//! TCP uses CONNECT. UDP uses one UDP ASSOCIATE per flow and stays UDP:
//! the datagram's destination is the address already on the packet.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use mirage_tcpip_stack::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::warn;

const FLOW_CAP: usize = 64;

pub async fn relay_tcp(mut listener: TcpListener, proxy: SocketAddr, cancel: CancellationToken) {
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => break,
            next = listener.next() => next,
        };
        let Some((app, _local, remote)) = next else {
            break;
        };
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(err) = relay_one_tcp(app, remote, proxy, cancel).await {
                warn!(%remote, error = %err, "tcp relay ended");
            }
        });
    }
}

async fn relay_one_tcp(
    mut app: mirage_tcpip_stack::TcpStream,
    remote: SocketAddr,
    proxy: SocketAddr,
    cancel: CancellationToken,
) -> Result<(), String> {
    let mut socks = TcpStream::connect(proxy)
        .await
        .map_err(|err| err.to_string())?;
    socks5_greeting(&mut socks).await?;
    socks5_connect(&mut socks, remote).await?;
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        copy = tokio::io::copy_bidirectional(&mut app, &mut socks) => {
            copy.map(|_| ()).map_err(|err| err.to_string())
        }
    }
}

pub async fn relay_udp(socket: UdpSocket, proxy: SocketAddr, cancel: CancellationToken) {
    let (mut read, write) = socket.split();
    let write = Arc::new(tokio::sync::Mutex::new(write));
    let mut flows: HashMap<(SocketAddr, SocketAddr), UdpFlow> = HashMap::new();

    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => break,
            msg = read.next() => msg,
        };
        let Some((payload, local, remote)) = msg else {
            break;
        };
        let key = (local, remote);
        if !flows.contains_key(&key) {
            if flows.len() >= FLOW_CAP {
                warn!("udp relay: flow cap reached, datagram dropped");
                continue;
            }
            match open_udp_flow(proxy, local, remote, Arc::clone(&write), cancel.clone()).await {
                Ok(flow) => {
                    flows.insert(key, flow);
                }
                Err(err) => {
                    warn!(%local, %remote, error = %err, "udp associate failed");
                    continue;
                }
            }
        }
        let udp = flows.get(&key).map(|flow| Arc::clone(&flow.udp));
        let Some(udp) = udp else {
            continue;
        };
        let frame = socks5_udp_frame(&payload, remote);
        if udp.send(&frame).await.is_err() {
            flows.remove(&key);
        }
    }
}

struct UdpFlow {
    _ctrl: TcpStream,
    udp: Arc<tokio::net::UdpSocket>,
}

async fn open_udp_flow(
    proxy: SocketAddr,
    local: SocketAddr,
    remote: SocketAddr,
    write: Arc<tokio::sync::Mutex<mirage_tcpip_stack::udp::WriteHalf>>,
    cancel: CancellationToken,
) -> Result<UdpFlow, String> {
    let mut ctrl = TcpStream::connect(proxy)
        .await
        .map_err(|err| err.to_string())?;
    socks5_greeting(&mut ctrl).await?;
    let relay = socks5_udp_associate(&mut ctrl, local).await?;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|err| err.to_string())?;
    udp.connect(relay).await.map_err(|err| err.to_string())?;
    let udp = Arc::new(udp);
    let reader = Arc::clone(&udp);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let read = tokio::select! {
                _ = cancel.cancelled() => break,
                read = reader.recv(&mut buf) => read,
            };
            let Ok(n) = read else { break };
            let Some(payload) = strip_socks5_udp(&buf[..n]) else {
                continue;
            };
            let mut sink = write.lock().await;
            let item = (payload, remote, local);
            if sink.send(item).await.is_err() {
                break;
            }
        }
    });
    Ok(UdpFlow { _ctrl: ctrl, udp })
}

async fn socks5_greeting(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|err| err.to_string())?;
    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|err| err.to_string())?;
    if resp[0] != 0x05 || resp[1] == 0xFF {
        return Err("socks5 auth refused".to_owned());
    }
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream, remote: SocketAddr) -> Result<(), String> {
    let req = socks5_request(0x01, remote);
    stream
        .write_all(&req)
        .await
        .map_err(|err| err.to_string())?;
    // This listener's CONNECT reply is a fixed IPv4 BND of 0.0.0.0:0.
    let mut resp = [0u8; 10];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|err| err.to_string())?;
    if resp[1] != 0x00 {
        return Err(format!("socks5 connect refused {}", resp[1]));
    }
    Ok(())
}

async fn socks5_udp_associate(stream: &mut TcpStream, local: SocketAddr) -> Result<SocketAddr, String> {
    let req = match local {
        SocketAddr::V4(_) => vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        SocketAddr::V6(_) => {
            let mut req = vec![0x05, 0x03, 0x00, 0x04];
            req.extend_from_slice(&[0u8; 16]);
            req.extend_from_slice(&[0, 0]);
            req
        }
    };
    stream
        .write_all(&req)
        .await
        .map_err(|err| err.to_string())?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|err| err.to_string())?;
    if head[1] != 0x00 {
        return Err(format!("socks5 udp associate refused {}", head[1]));
    }
    let addr = read_socks_addr(stream, head[3]).await?;
    Ok(addr)
}

async fn read_socks_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr, String> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|err| err.to_string())?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|err| err.to_string())?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        other => Err(format!("socks5 atyp {other}")),
    }
}

fn socks5_request(cmd: u8, remote: SocketAddr) -> Vec<u8> {
    let mut req = vec![0x05, cmd, 0x00];
    match remote {
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
    req
}

fn socks5_udp_frame(payload: &[u8], remote: SocketAddr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 22);
    frame.extend_from_slice(&[0x00, 0x00, 0x00]);
    match remote {
        SocketAddr::V4(v4) => {
            frame.push(0x01);
            frame.extend_from_slice(&v4.ip().octets());
            frame.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            frame.push(0x04);
            frame.extend_from_slice(&v6.ip().octets());
            frame.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

fn strip_socks5_udp(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 4 || frame[2] != 0 {
        return None;
    }
    let header = match frame[3] {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            let len = *frame.get(4)? as usize;
            4 + 1 + len + 2
        }
        _ => return None,
    };
    frame.get(header..).map(|payload| payload.to_vec())
}
