//! Android TUN device and socket protector.
//!
//! `AndroidTunDevice` wraps the raw file descriptor received from Kotlin
//! (`VpnService.Builder.establish()`) for async read/write.
//!
//! `SocketProtector` holds a `GlobalRef` to the Kotlin `VpnService` instance
//! and calls `VpnService.protect(fd)` via JNI to exempt outbound tunnel
//! sockets from being captured by the VPN.

use async_trait::async_trait;
use mirage_tun_core::{error::TunError, traits::private};

// ── AndroidTunDevice ─────────────────────────────────────────────────────────

/// Wraps the raw TUN file descriptor supplied by Android's VpnService.
///
/// Lifetime is owned by the Kotlin `ParcelFileDescriptor` — Rust only
/// reads and writes; it does not close the fd.
pub struct AndroidTunDevice {
    /// fd from `ParcelFileDescriptor.getFd()`.
    fd: std::os::raw::c_int,
    /// Interface name (virtual — Android does not expose a real name).
    name: String,
    /// Async wrapper around the fd, created on Android only.
    #[cfg(target_os = "android")]
    inner: tokio::io::unix::AsyncFd<OwnedFd>,
}

/// SAFETY: The fd is valid for the lifetime of the Kotlin `ParcelFileDescriptor`,
/// which the caller guarantees outlives this struct.
unsafe impl Send for AndroidTunDevice {}
unsafe impl Sync for AndroidTunDevice {}

#[cfg(target_os = "android")]
struct OwnedFd(std::os::raw::c_int);

#[cfg(target_os = "android")]
impl std::os::unix::io::AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> std::os::raw::c_int {
        self.0
    }
}

impl AndroidTunDevice {
    /// Wrap `fd` obtained from `ParcelFileDescriptor.getFd()`.
    ///
    /// # Safety
    /// `fd` must be a valid, open file descriptor for the VPN TUN interface
    /// and must remain open for the lifetime of this value.
    pub fn from_fd(fd: std::os::raw::c_int) -> std::io::Result<Self> {
        #[cfg(target_os = "android")]
        {
            // Put the fd into non-blocking mode so AsyncFd works correctly.
            // SAFETY: fd is valid (caller guarantee).
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let inner = tokio::io::unix::AsyncFd::new(OwnedFd(fd))?;
            Ok(Self {
                fd,
                name: "vpn".to_owned(),
                inner,
            })
        }

        #[cfg(not(target_os = "android"))]
        Ok(Self {
            fd,
            name: "vpn".to_owned(),
        })
    }

    /// Raw fd for use in channel pump.
    pub fn raw_fd(&self) -> std::os::raw::c_int {
        self.fd
    }

    /// Read one raw IP packet from the TUN fd.
    ///
    /// Returns the number of bytes read into `buf`.
    #[cfg(target_os = "android")]
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                // SAFETY: fd is valid, buf lives for this call.
                let n = unsafe {
                    libc::read(
                        inner.get_ref().0,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one raw IP packet into the TUN fd.
    #[cfg(target_os = "android")]
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                // SAFETY: fd is valid, buf lives for this call.
                let n = unsafe {
                    libc::write(
                        inner.get_ref().0,
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Non-Android stub — never called at runtime.
    #[cfg(not(target_os = "android"))]
    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AndroidTunDevice not supported on this platform",
        ))
    }

    /// Non-Android stub — never called at runtime.
    #[cfg(not(target_os = "android"))]
    pub async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "AndroidTunDevice not supported on this platform",
        ))
    }
}

impl private::Sealed for AndroidTunDevice {}

#[async_trait]
impl mirage_tun_core::traits::TunDevice for AndroidTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    /// No-op: VpnService owns the TUN interface lifecycle.
    async fn configure(&mut self, _addr: &str, _mtu: u16) -> Result<(), TunError> {
        Ok(())
    }

    /// No-op: Kotlin's `ParcelFileDescriptor.close()` handles teardown.
    async fn close(self) -> Result<(), TunError> {
        Ok(())
    }
}

// ── SocketProtector ──────────────────────────────────────────────────────────

/// Calls `VpnService.protect(fd)` via JNI so outbound tunnel sockets are not
/// captured by the VPN routing, preventing infinite loops.
///
/// Only meaningful on Android; a no-op stub is provided for other targets.
pub struct SocketProtector {
    #[cfg(target_os = "android")]
    inner: AndroidSocketProtector,
}

#[cfg(target_os = "android")]
struct AndroidSocketProtector {
    vm: jni::JavaVM,
    service_ref: jni::objects::GlobalRef,
}

impl SocketProtector {
    /// Build from the raw JavaVM pointer and a `GlobalRef` to the
    /// `VpnService` Java object.
    ///
    /// # Android
    /// Created inside `jni_bridge::start` where both are available.
    ///
    /// # Other platforms
    /// Returns a no-op protector.
    #[cfg(target_os = "android")]
    pub fn new(vm: jni::JavaVM, service_ref: jni::objects::GlobalRef) -> Self {
        Self {
            inner: AndroidSocketProtector { vm, service_ref },
        }
    }

    #[cfg(not(target_os = "android"))]
    pub fn new() -> Self {
        Self {}
    }

    /// Exempt `fd` from VPN routing by calling `VpnService.protect(fd)`.
    ///
    /// Must be called on every outbound socket before `connect()`.
    #[cfg(target_os = "android")]
    pub fn protect(&self, fd: i32) -> Result<(), crate::error::AndroidTunError> {
        use jni::objects::JValue;
        let mut env = self
            .inner
            .vm
            .attach_current_thread()
            .map_err(|e| crate::error::AndroidTunError::Jni(e.to_string()))?;
        env.call_method(
            &self.inner.service_ref,
            "protect",
            "(I)Z",
            &[JValue::Int(fd)],
        )
        .map_err(|e| crate::error::AndroidTunError::Jni(e.to_string()))?;
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    pub fn protect(&self, _fd: i32) -> Result<(), crate::error::AndroidTunError> {
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
impl Default for SocketProtector {
    fn default() -> Self {
        Self::new()
    }
}
