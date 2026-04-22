//! Byte blob management for WFP conditions.

use std::ffi::OsStr;
use std::io;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
};

use crate::to_wide_null;

/// An owned `FWP_BYTE_BLOB`, freed via `FwpmFreeMemory0` or dropped as a `Vec`.
pub struct OwnedByteBlob {
    inner: InnerBlob,
}

enum InnerBlob {
    Pointer { blob: *mut FWP_BYTE_BLOB },
    Vec { blob: FWP_BYTE_BLOB, _buf: Box<[u8]> },
}

impl OwnedByteBlob {
    /// Take ownership of a pointer that must be freed with `FwpmFreeMemory0`.
    ///
    /// # Safety
    /// `blob` must be a valid pointer returned by a WFP API that allocates via `FwpmAllocate`.
    pub unsafe fn from_raw(blob: *mut FWP_BYTE_BLOB) -> Self {
        Self { inner: InnerBlob::Pointer { blob } }
    }

    /// Pointer to the underlying blob.
    pub fn as_ptr(&self) -> *const FWP_BYTE_BLOB {
        match &self.inner {
            InnerBlob::Pointer { blob } => *blob,
            InnerBlob::Vec { blob, .. } => blob,
        }
    }
}

// SAFETY: WFP blob pointers are used read-only after construction; no concurrent mutation
unsafe impl Send for OwnedByteBlob {}

impl<T: AsRef<[u8]>> From<T> for OwnedByteBlob {
    fn from(value: T) -> Self {
        let buf: Box<[u8]> = Box::from(value.as_ref());
        let blob = FWP_BYTE_BLOB {
            data: buf.as_ptr() as _,
            size: u32::try_from(buf.len()).expect("blob size fits u32"),
        };
        Self { inner: InnerBlob::Vec { blob, _buf: buf } }
    }
}

impl Drop for OwnedByteBlob {
    fn drop(&mut self) {
        if let InnerBlob::Pointer { mut blob } = self.inner {
            // SAFETY: pointer was allocated by WFP and must be freed with FwpmFreeMemory0
            unsafe { FwpmFreeMemory0(&mut blob as *mut _ as *mut _) };
        }
    }
}

/// Returns an app-ID blob for `path` using `FwpmGetAppIdFromFileName0`.
pub fn app_id_from_filename(path: impl AsRef<OsStr>) -> io::Result<OwnedByteBlob> {
    let wide = to_wide_null(path);
    let mut blob = std::ptr::null_mut();
    let status = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: blob is a valid pointer returned by FwpmGetAppIdFromFileName0
    Ok(unsafe { OwnedByteBlob::from_raw(blob) })
}
