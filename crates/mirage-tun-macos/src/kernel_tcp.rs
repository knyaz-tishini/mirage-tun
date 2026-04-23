/// macOS kernel-TCP acceptor.
///
/// macOS routes all TCP traffic through the kernel stack. The pf `rdr` rule
/// (installed by `MacosFirewall`) redirects TCP packets arriving on the TUN
/// interface to `127.0.0.1:{intercept_port}`.
///
/// We bind a `TcpListener` on that port and yield incoming connections.
///
/// Original destination recovery: pf's `rdr` preserves the original destination
/// in the socket's local address when the redirected connection is accepted —
/// `getsockname()` on the accepted socket returns the *original* destination IP
/// and port. On macOS this works because pf inserts destination NAT state and
/// `getsockname` returns the pre-NAT address via the socket's received address.
///
/// Note: If `getsockname` returns `127.0.0.1` (i.e. pf did not preserve the
/// original dst), we fall back to `(0.0.0.0:0, peer_addr)` so the caller can
/// still handle the connection as a transparent proxy.
use crate::error::MacosTunError;
use async_trait::async_trait;
use mirage_tun_core::traits::TcpAcceptor;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

/// Listens on `127.0.0.1:{intercept_port}` for connections redirected by pf.
pub struct MacosKernelTcpAcceptor {
    listener: TcpListener,
    intercept_port: u16,
}

impl MacosKernelTcpAcceptor {
    /// Bind the intercept listener.
    pub async fn bind(intercept_port: u16) -> Result<Self, MacosTunError> {
        let bind_addr = format!("127.0.0.1:{}", intercept_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(MacosTunError::ListenerBind)?;
        debug!("TCP intercept listener bound on {}", bind_addr);
        Ok(MacosKernelTcpAcceptor {
            listener,
            intercept_port,
        })
    }

    pub fn intercept_port(&self) -> u16 {
        self.intercept_port
    }
}

#[async_trait]
impl TcpAcceptor for MacosKernelTcpAcceptor {
    /// Accept the next redirected TCP connection.
    ///
    /// Returns `(stream, original_dst, peer_addr)`.
    ///
    /// `original_dst`: the destination address the device app originally
    /// connected to (recovered via `getsockname` on the accepted socket).
    ///
    /// `peer_addr`: the source address of the device app.
    async fn accept(&mut self) -> Option<(TcpStream, SocketAddr, SocketAddr)> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let original_dst = recover_original_dst(&stream, peer_addr);
                    debug!(
                        "TCP accept: peer={} orig_dst={}",
                        peer_addr, original_dst
                    );
                    return Some((stream, original_dst, peer_addr));
                }
                Err(e) => {
                    warn!("TCP intercept accept error: {}", e);
                    // Non-fatal — retry
                }
            }
        }
    }
}

/// Attempt to recover the original destination address from a pf-redirected socket.
///
/// On macOS, pf `rdr` redirects the connection to the intercept port. The kernel
/// records the original destination in the socket's local address via the NAT state.
/// Calling `getsockname()` on the raw fd returns this pre-NAT address.
///
/// If recovery fails or returns the loopback address (meaning pf NAT state is not
/// available), returns a zeroed `SocketAddr` as a sentinel.
fn recover_original_dst(stream: &TcpStream, peer_addr: SocketAddr) -> SocketAddr {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();

        // getsockname returns the local address of the accepted socket.
        // When pf rdr redirected the connection, this should be the original dst.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockname(
                fd,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if ret == 0 {
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            let sock_addr = SocketAddr::from((ip, port));

            // If getsockname returns 127.0.0.1 it means pf did NOT preserve the
            // original dst (or the rule is missing). Fall through to fallback.
            if !ip.is_loopback() {
                return sock_addr;
            }
        }

        // Fallback: we cannot determine original dst.
        // Use peer IP with port 0 as a hint — caller must treat port 0 as unknown.
        let fallback_ip = match peer_addr {
            SocketAddr::V4(v4) => SocketAddr::from((*v4.ip(), 0)),
            SocketAddr::V6(v6) => SocketAddr::from((*v6.ip(), 0)),
        };
        warn!(
            "could not recover original dst for peer {}, using {}",
            peer_addr, fallback_ip
        );
        fallback_ip
    }

    #[cfg(not(target_os = "macos"))]
    {
        // On non-macOS builds just return a zeroed addr
        let _ = (stream, peer_addr);
        "0.0.0.0:0".parse().unwrap()
    }
}
