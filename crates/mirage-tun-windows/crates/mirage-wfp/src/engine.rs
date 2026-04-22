//! WFP engine session management.

use std::io;
use std::mem;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FwpmEngineClose0, FwpmEngineOpen0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

/// Active connection to the WFP engine. `Send` but not `Sync`.
pub struct WfpEngine {
    handle: HANDLE,
}

// SAFETY: handle is a kernel object; moving and sharing across threads is safe.
// WFP engine handles are thread-safe for concurrent use.
unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Opens a dynamic session — filters removed automatically when engine drops.
    pub fn open_dynamic() -> io::Result<Self> {
        let mut session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        Self::open_with_session(session)
    }

    /// Opens a persistent session — filters survive engine drop.
    pub fn open() -> io::Result<Self> {
        let session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        Self::open_with_session(session)
    }

    fn open_with_session(session: FWPM_SESSION0) -> io::Result<Self> {
        let mut handle: HANDLE = ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null_mut(),
                RPC_C_AUTHN_DEFAULT as u32,
                ptr::null_mut(),
                &session,
                &mut handle,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        tracing::debug!("WFP engine opened");
        Ok(Self { handle })
    }
}

impl AsRawHandle for WfpEngine {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        // SAFETY: handle is valid and owned exclusively by this struct
        unsafe { FwpmEngineClose0(self.handle) };
        tracing::debug!("WFP engine closed");
    }
}
