use std::net::SocketAddr;
use async_trait::async_trait;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use mirage_tun_core::traits::TcpAcceptor;

/// SO_ORIGINAL_DST socket option (for IPv4).
/// Defined in <linux/netfilter_ipv4.h> as 80.
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

/// TCP acceptor that receives connections redirected from the TUN interface
/// via nftables/iptables REDIRECT rule. Recovers original destination via
/// SO_ORIGINAL_DST getsockopt.
pub struct LinuxKernelTcpAcceptor {
    listener: TcpListener,
}

impl LinuxKernelTcpAcceptor {
    /// Bind to 0.0.0.0:port. The REDIRECT rule sends all intercepted TCP here.
    pub async fn bind(port: u16) -> std::io::Result<Self> {
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!("TCP acceptor bound on {addr}");
        Ok(Self { listener })
    }
}

#[async_trait]
impl TcpAcceptor for LinuxKernelTcpAcceptor {
    async fn accept(&mut self) -> Option<(TcpStream, SocketAddr, SocketAddr)> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Recover original destination.
                    let orig_dst = match get_original_dst(&stream) {
                        Ok(dst) => dst,
                        Err(e) => {
                            warn!("SO_ORIGINAL_DST failed for {peer_addr}: {e}");
                            // Fall back to local addr (intercept port).
                            match stream.local_addr() {
                                Ok(a) => a,
                                Err(_) => continue,
                            }
                        }
                    };
                    debug!("TCP accept: peer={peer_addr} orig_dst={orig_dst}");
                    // Return (orig_dst = local_addr, peer_addr) matching trait signature:
                    // (stream, local_addr/orig_dst, peer_addr)
                    return Some((stream, orig_dst, peer_addr));
                }
                Err(e) => {
                    warn!("TcpListener accept error: {e}");
                    return None;
                }
            }
        }
    }
}

/// Retrieve original destination from NAT conntrack via SO_ORIGINAL_DST.
#[cfg(target_os = "linux")]
fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut sockaddr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let ip = std::net::Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr));
    let port = u16::from_be(sockaddr.sin_port);
    Ok(SocketAddr::from((ip, port)))
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    // On non-Linux builds return local addr as placeholder.
    stream.local_addr()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::SO_ORIGINAL_DST;

    #[test]
    fn so_original_dst_value() {
        // Must be 80 per linux/netfilter_ipv4.h
        assert_eq!(SO_ORIGINAL_DST, 80);
    }
}
