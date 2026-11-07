use crate::error::LinuxTunError;
use mirage_tun_core::error::TunError;
use mirage_tun_core::traits::{TunDevice, private};
use async_trait::async_trait;

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

/// Linux TUN device backed by /dev/net/tun.
pub struct LinuxTunDevice {
    name: String,
    #[cfg(target_os = "linux")]
    _fd: std::fs::File,
}

#[cfg(target_os = "linux")]
impl LinuxTunDevice {
    /// Open /dev/net/tun and allocate an interface named `name` (e.g. "tun0").
    /// Empty name lets the kernel auto-assign ("tun%d").
    pub fn open(name: &str) -> Result<Self, LinuxTunError> {
        use std::ffi::CStr;
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/net/tun")?;

        let fd = file.as_raw_fd();

        // Build ifreq: name + flags
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        // Safety: ifr_name is a C char array; zeroed above so null-terminated.
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                ifr.ifr_name.as_mut_ptr(),
                copy_len,
            );
            // IFF_TUN | IFF_NO_PI
            ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
        }

        // TUNSETIFF
        let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_ulong, &ifr as *const _) };
        if ret < 0 {
            return Err(LinuxTunError::Open(std::io::Error::last_os_error()));
        }

        // Extract the actual assigned name from ifr_name
        let actual_name = {
            let raw = unsafe {
                CStr::from_ptr(ifr.ifr_name.as_ptr())
            };
            raw.to_string_lossy().into_owned()
        };

        tracing::debug!("Opened TUN device: {actual_name}");

        Ok(Self {
            name: actual_name,
            _fd: file,
        })
    }

    pub fn raw_fd(&self) -> RawFd {
        self._fd.as_raw_fd()
    }
}

#[cfg(not(target_os = "linux"))]
impl LinuxTunDevice {
    pub fn open(_name: &str) -> Result<Self, LinuxTunError> {
        Err(LinuxTunError::Other("LinuxTunDevice only supported on Linux".into()))
    }
}

impl private::Sealed for LinuxTunDevice {}

#[async_trait]
impl TunDevice for LinuxTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn configure(&mut self, addr: &str, mtu: u16) -> Result<(), TunError> {
        configure_tun_interface(&self.name, addr, mtu).await
            .map_err(|e| TunError::Other(e.to_string()))
    }

    async fn close(self) -> Result<(), TunError> {
        // Dropping the fd closes the device — Linux removes tun0 automatically.
        tracing::debug!("Closing TUN device: {}", self.name);
        Ok(())
    }
}

/// Configure address and bring up the TUN interface via `ip` commands.
async fn configure_tun_interface(
    name: &str,
    addr: &str,
    mtu: u16,
) -> Result<(), LinuxTunError> {
    run_ip(&["addr", "add", addr, "dev", name]).await?;
    run_ip(&["link", "set", name, "up"]).await?;
    run_ip(&["link", "set", name, "mtu", &mtu.to_string()]).await?;
    tracing::info!("TUN {name} configured: addr={addr} mtu={mtu}");
    Ok(())
}

/// Run `ip <args>` and return an error if exit code != 0.
pub(crate) async fn run_ip(args: &[&str]) -> Result<(), LinuxTunError> {
    use tokio::process::Command;
    let out = Command::new("ip")
        .args(args)
        .output()
        .await?;
    tracing::debug!("ip {}: status={}", args.join(" "), out.status);
    if !out.stdout.is_empty() {
        tracing::debug!("ip stdout: {}", String::from_utf8_lossy(&out.stdout));
    }
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        tracing::warn!("ip {} failed: {stderr}", args.join(" "));
        return Err(LinuxTunError::Routing(format!(
            "ip {} failed (exit {}): {stderr}",
            args.join(" "),
            out.status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}
