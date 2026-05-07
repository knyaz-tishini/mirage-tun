/// macOS utun TUN device implementation.
///
/// Creates a utun interface via PF_SYSTEM kernel control socket.
/// Every packet read from the fd has a 4-byte big-endian AF prefix prepended by the kernel.
/// Every packet written must include the same 4-byte prefix.
use crate::error::MacosTunError;
use async_trait::async_trait;
use mirage_tun_core::error::TunError;
use mirage_tun_core::traits::{TunDevice, private::Sealed};

// ── macOS implementation ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    use tracing::debug;

    pub const PF_SYSTEM: libc::c_int = 32;
    pub const SYSPROTO_CONTROL: libc::c_int = 2;
    pub const AF_SYS_CONTROL: u16 = 2;
    pub const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";
    pub const UTUN_OPT_IFNAME: libc::c_int = 2;
    pub const CTLIOCGINFO: u64 = 0xC0644E03;

    #[repr(C)]
    pub struct CtlInfo {
        pub ctl_id: u32,
        pub ctl_name: [libc::c_char; 96],
    }

    #[repr(C)]
    pub struct SockaddrCtl {
        pub sc_len: u8,
        pub sc_family: u8,
        pub ss_sysaddr: u16,
        pub sc_id: u32,
        pub sc_unit: u32,
        pub sc_reserved: [u32; 5],
    }

    /// macOS utun device.
    pub struct MacosTunDevice {
        pub name: String,
        /// Owns the fd — drop destroys the utun interface.
        pub _fd: std::os::unix::io::OwnedFd,
        pub async_file: tokio::io::unix::AsyncFd<std::fs::File>,
    }

    impl MacosTunDevice {
        pub fn open(unit: u32) -> Result<Self, MacosTunError> {
            use std::mem;

            let fd = unsafe {
                libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL)
            };
            if fd < 0 {
                return Err(MacosTunError::UtunCreate(
                    std::io::Error::last_os_error().to_string(),
                ));
            }

            let mut ctl_info: CtlInfo = unsafe { mem::zeroed() };
            let name_bytes = UTUN_CONTROL_NAME;
            let copy_len = name_bytes.len().min(ctl_info.ctl_name.len());
            for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                ctl_info.ctl_name[i] = b as i8;
            }

            if unsafe {
                libc::ioctl(fd, CTLIOCGINFO as libc::c_ulong, &mut ctl_info as *mut CtlInfo)
            } < 0
            {
                let err = std::io::Error::last_os_error().to_string();
                unsafe { libc::close(fd) };
                return Err(MacosTunError::UtunIoctl(err));
            }

            let sc = SockaddrCtl {
                sc_len: mem::size_of::<SockaddrCtl>() as u8,
                sc_family: PF_SYSTEM as u8,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: ctl_info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };

            if unsafe {
                libc::connect(
                    fd,
                    &sc as *const SockaddrCtl as *const libc::sockaddr,
                    mem::size_of::<SockaddrCtl>() as libc::socklen_t,
                )
            } < 0
            {
                let err = std::io::Error::last_os_error().to_string();
                unsafe { libc::close(fd) };
                return Err(MacosTunError::UtunConnect(err));
            }

            let mut ifname_buf = [0u8; 64];
            let mut ifname_len = ifname_buf.len() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd,
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    ifname_buf.as_mut_ptr() as *mut libc::c_void,
                    &mut ifname_len,
                )
            } < 0
            {
                let err = std::io::Error::last_os_error().to_string();
                unsafe { libc::close(fd) };
                return Err(MacosTunError::UtunIfname(err));
            }

            let name_len = ifname_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(ifname_len as usize);
            let name = String::from_utf8_lossy(&ifname_buf[..name_len]).to_string();

            // Set non-blocking
            unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };

            tracing::info!("utun interface created: {}", name);

            // SAFETY: fd is valid and exclusively owned here.
            let owned_fd = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) };
            let dup_fd = owned_fd.try_clone().map_err(MacosTunError::Io)?;
            let std_file = unsafe { std::fs::File::from_raw_fd(dup_fd.into_raw_fd()) };
            let async_file = tokio::io::unix::AsyncFd::new(std_file)
                .map_err(MacosTunError::Io)?;

            Ok(MacosTunDevice {
                name,
                _fd: owned_fd,
                async_file,
            })
        }

        pub async fn read_packet(&self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
            use std::os::unix::io::AsRawFd;
            use tokio::io::Interest;

            let mut raw = vec![0u8; 4 + 1504];
            loop {
                let mut guard = self.async_file.ready(Interest::READABLE).await?;
                match guard.try_io(|file| {
                    let n = unsafe {
                        libc::read(
                            file.get_ref().as_raw_fd(),
                            raw.as_mut_ptr() as *mut libc::c_void,
                            raw.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) if n > 4 => {
                        buf.clear();
                        buf.extend_from_slice(&raw[4..n]);
                        return Ok(n - 4);
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn write_packet(&self, packet: &[u8]) -> std::io::Result<usize> {
            use std::os::unix::io::AsRawFd;
            use tokio::io::Interest;

            if packet.is_empty() {
                return Ok(0);
            }

            let af: u32 = if packet[0] >> 4 == 6 {
                libc::AF_INET6 as u32
            } else {
                libc::AF_INET as u32
            };
            let af_be = af.to_be_bytes();

            loop {
                let mut guard = self.async_file.ready(Interest::WRITABLE).await?;
                match guard.try_io(|file| {
                    let iov = [
                        libc::iovec {
                            iov_base: af_be.as_ptr() as *mut libc::c_void,
                            iov_len: 4,
                        },
                        libc::iovec {
                            iov_base: packet.as_ptr() as *mut libc::c_void,
                            iov_len: packet.len(),
                        },
                    ];
                    let n = unsafe {
                        libc::writev(file.get_ref().as_raw_fd(), iov.as_ptr(), 2)
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }

        pub fn interface_name(&self) -> &str {
            &self.name
        }
    }

    impl Sealed for MacosTunDevice {}

    #[async_trait]
    impl TunDevice for MacosTunDevice {
        fn name(&self) -> &str {
            &self.name
        }

        async fn configure(&mut self, addr: &str, mtu: u16) -> Result<(), TunError> {
            configure_interface(&self.name, addr, mtu)
                .await
                .map_err(|e| TunError::Other(e.to_string()))
        }

        async fn close(self) -> Result<(), TunError> {
            debug!("closing utun interface {}", self.name);
            Ok(())
        }
    }

    pub async fn configure_interface(
        iface: &str,
        addr_cidr: &str,
        mtu: u16,
    ) -> Result<(), MacosTunError> {
        use tokio::process::Command;

        let addr = addr_cidr.split('/').next().unwrap_or(addr_cidr);
        // P2P utun: derive a distinct peer IP so the kernel accepts a /0 route
        // through it.  WireGuard / Tailscale do the same — local x.x.x.2,
        // peer x.x.x.1.  Same-IP P2P (`utun3 10.7.0.2 10.7.0.2`) blocks
        // `route add 0.0.0.0/0 <peer>` with "Network is unreachable".
        let peer = derive_peer(addr);

        let out = Command::new("ifconfig")
            .args([iface, addr, &peer, "mtu", &mtu.to_string(), "up"])
            .output()
            .await
            .map_err(MacosTunError::Io)?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            tracing::error!("ifconfig failed: {}", stderr);
            return Err(MacosTunError::Ifconfig(stderr));
        }

        debug!("configured {} addr={} peer={} mtu={}", iface, addr, peer, mtu);
        Ok(())
    }

    fn derive_peer(local: &str) -> String {
        let parts: Vec<&str> = local.split('.').collect();
        if parts.len() == 4 {
            if let Ok(last) = parts[3].parse::<u8>() {
                let peer_last = if last == 1 { 2 } else { 1 };
                return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], peer_last);
            }
        }
        local.to_string()
    }
}

// ── Non-macOS stub ────────────────────────────────────────────────────────────

#[cfg(not(target_os = "macos"))]
mod stub_impl {
    use super::*;

    pub struct MacosTunDevice {
        pub name: String,
    }

    impl MacosTunDevice {
        pub fn open(_unit: u32) -> Result<Self, MacosTunError> {
            Err(MacosTunError::Other(
                "MacosTunDevice is only available on macOS".to_string(),
            ))
        }

        pub async fn read_packet(&self, _buf: &mut Vec<u8>) -> std::io::Result<usize> {
            Err(std::io::Error::other("not available on this platform"))
        }

        pub async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("not available on this platform"))
        }

        pub fn interface_name(&self) -> &str {
            &self.name
        }
    }

    impl Sealed for MacosTunDevice {}

    #[async_trait]
    impl TunDevice for MacosTunDevice {
        fn name(&self) -> &str {
            &self.name
        }

        async fn configure(&mut self, _addr: &str, _mtu: u16) -> Result<(), TunError> {
            Err(TunError::Other(
                "MacosTunDevice not available on this platform".to_string(),
            ))
        }

        async fn close(self) -> Result<(), TunError> {
            Ok(())
        }
    }
}

// ── Re-export the correct implementation ──────────────────────────────────────

#[cfg(target_os = "macos")]
pub use macos_impl::MacosTunDevice;
#[cfg(target_os = "macos")]
pub(crate) use macos_impl::configure_interface;

#[cfg(not(target_os = "macos"))]
pub use stub_impl::MacosTunDevice;
