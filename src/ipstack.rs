use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use mirage_dns::DnsResolver;

use mirage_ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, debug};

use crate::error::Result;
use crate::wintun::WintunDevice;

pub struct IpStackRunner;

impl IpStackRunner {
    pub async fn start(
        device: WintunDevice,
        socks5_addr: SocketAddr,
        cancel: CancellationToken,
        relay_addrs: Vec<IpAddr>,
        if_index: u32,
        dns_resolver: DnsResolver,
    ) -> Result<Self> {
        info!("IpStackRunner: started, socks5={socks5_addr}, relay_bypass={relay_addrs:?}, if_index={if_index}");

        let relay_set: HashSet<Ipv4Addr> = relay_addrs
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();

        let mut config = IpStackConfig::default();
        config.mtu_unchecked(1500);

        let mut stack = IpStack::new(config, device);

        let socks5_semaphore = Arc::new(Semaphore::new(100));
        let start_time = std::time::Instant::now();

        // Single accept loop — replaces all 5+ tasks from the old netstack-smoltcp approach
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        info!("IpStackRunner: cancelled, exiting accept loop");
                        break;
                    }
                    result = stack.accept() => {
                        match result {
                            Ok(IpStackStream::Tcp(tcp_stream)) => {
                                let dst = tcp_stream.local_addr();

                                // Relay bypass: drop packets destined to relay servers
                                if let IpAddr::V4(v4) = dst.ip() {
                                    if relay_set.contains(&v4) {
                                        warn!("IpStackRunner: relay traffic in TUN, dropping dst={dst}");
                                        continue;
                                    }
                                }

                                debug!("IpStackRunner: TCP → {dst}");
                                let sem = socks5_semaphore.clone();
                                let cancel2 = cancel.clone();
                                tokio::spawn(async move {
                                    tokio::select! {
                                        _ = cancel2.cancelled() => {}
                                        result = handle_tcp(tcp_stream, socks5_addr, dst, sem, start_time, if_index) => {
                                            if let Err(e) = result {
                                                debug!("IpStackRunner: TCP {dst} error: {e}");
                                            }
                                        }
                                    }
                                });
                            }
                            Ok(IpStackStream::Udp(udp_stream)) => {
                                let dst = udp_stream.local_addr();

                                if dst.port() == 53 {
                                    debug!("IpStackRunner: UDP DNS → {dst}");
                                    let resolver = dns_resolver.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_dns_udp_stream(udp_stream, resolver).await {
                                            debug!("IpStackRunner: DNS {dst} error: {e}");
                                        }
                                    });
                                }
                            }
                            Ok(IpStackStream::UnknownTransport(_)) | Ok(IpStackStream::UnknownNetwork(_)) => {
                                // Ignore non-TCP/UDP
                            }
                            Err(e) => {
                                warn!("IpStackRunner: accept error: {e}");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self)
    }
}

// ── TCP → SOCKS5 ──────────────────────────────────────────────────────────────

async fn handle_tcp(
    mut tcp: mirage_ipstack::IpStackTcpStream,
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    socks5_semaphore: Arc<Semaphore>,
    start_time: std::time::Instant,
    if_index: u32,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Stagger connections during startup to avoid thundering herd
    if start_time.elapsed() < std::time::Duration::from_secs(5) {
        let jitter = rand::random::<u64>() % 2000;
        tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
    }

    let mut proxy = socks5_connect_with_semaphore(socks5_addr, dst, &socks5_semaphore, if_index).await?;
    debug!("IpStackRunner: SOCKS5 connected to {dst}");
    tokio::io::copy_bidirectional(&mut tcp, &mut proxy).await?;
    Ok(())
}

// ── DNS UDP stream handler ──────────────────────────────────────────────────

async fn handle_dns_udp_stream(
    mut udp: mirage_ipstack::IpStackUdpStream,
    resolver: DnsResolver,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut query_buf = vec![0u8; 4096];
    // Handle multiple queries on the same UDP stream
    loop {
        let n = udp.read(&mut query_buf).await?;
        if n == 0 {
            break;
        }

        match resolver.resolve(&query_buf[..n]).await {
            Ok(response) => {
                udp.write_all(&response).await?;
            }
            Err(e) => {
                debug!("DNS resolve error: {e}");
                break;
            }
        }
    }
    Ok(())
}

// ── SOCKS5 connect with concurrency limit ────────────────────────────────────

async fn socks5_connect_with_semaphore(
    socks5_addr: SocketAddr,
    dst: SocketAddr,
    semaphore: &Semaphore,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let _permit = semaphore
        .acquire()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let mut last_err = None;
    for attempt in 0..3u8 {
        match socks5_connect(socks5_addr, dst, if_index).await {
            Ok(proxy) => return Ok(proxy),
            Err(e) => {
                warn!("IpStackRunner: SOCKS5 to {dst} attempt {attempt} failed: {e}");
                last_err = Some(e);
                if attempt < 2 {
                    // Exponential backoff: 200ms, 800ms
                    let delay = 200u64 * (1 << (attempt * 2));
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
    }
    Err(last_err.unwrap())
}

// ── Interface-bound TCP connect ───────────────────────────────────────────────

#[cfg(windows)]
async fn connect_via_interface(
    remote: SocketAddr,
    if_index: u32,
) -> std::io::Result<TcpStream> {
    use std::os::windows::io::AsRawSocket;
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if remote.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if if_index > 0 {
        unsafe {
            let handle = sock.as_raw_socket() as usize;
            let index_ne = if remote.is_ipv4() {
                u32::to_be(if_index)
            } else {
                if_index
            };
            let ret = windows_sys::Win32::Networking::WinSock::setsockopt(
                handle,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                31, // IP_UNICAST_IF
                &index_ne as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            );
            if ret == windows_sys::Win32::Networking::WinSock::SOCKET_ERROR {
                return Err(std::io::Error::from_raw_os_error(
                    windows_sys::Win32::Networking::WinSock::WSAGetLastError(),
                ));
            }
        }
    }

    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    let tokio_sock = tokio::net::TcpSocket::from_std_stream(std_stream);
    tokio_sock.connect(remote).await
}

#[cfg(not(windows))]
async fn connect_via_interface(
    remote: SocketAddr,
    _if_index: u32,
) -> std::io::Result<TcpStream> {
    TcpStream::connect(remote).await
}

// ── SOCKS5 no-auth connect ────────────────────────────────────────────────────

async fn socks5_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    if_index: u32,
) -> std::result::Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = connect_via_interface(proxy, if_index).await?;

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
