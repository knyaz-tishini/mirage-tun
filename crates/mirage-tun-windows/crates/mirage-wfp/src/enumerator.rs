//! WFP filter enumeration.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmFreeMemory0,
};

use crate::transaction::WfpTransaction;

/// Iterator over WFP filters via `FwpmFilterEnum0`.
pub struct FilterEnumerator<'a, 'b: 'a> {
    tx: &'a WfpTransaction<'b>,
    enum_handle: HANDLE,
    exhausted: bool,
    entries: *mut *mut FWPM_FILTER0,
    num_entries: u32,
    index: u32,
}

impl<'a, 'b> FilterEnumerator<'a, 'b> {
    /// Create an enumerator for all filters.
    pub fn new(tx: &'a WfpTransaction<'b>) -> io::Result<Self> {
        let mut handle = HANDLE::default();
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(tx.engine.as_raw_handle(), ptr::null_mut(), &mut handle)
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            tx,
            enum_handle: handle,
            exhausted: false,
            entries: ptr::null_mut(),
            num_entries: 0,
            index: 0,
        })
    }

    /// Advance to the next filter. Returns `None` when exhausted.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<io::Result<FilterEnumItem<'a, 'b, '_>>> {
        const BATCH: u32 = 50;

        if self.exhausted {
            return None;
        }

        // Serve from current batch.
        if self.index < self.num_entries {
            let idx = self.index as usize;
            // SAFETY: entries array is valid; FilterEnumItem borrows self so ptr lives long enough
            let filter = unsafe { &**self.entries.add(idx) };
            self.index += 1;
            return Some(Ok(FilterEnumItem { filter, _enum: self }));
        }

        let prev = self.num_entries;
        self.free_entries();

        // Previous batch was a short read → done.
        if prev != 0 && prev < BATCH {
            self.exhausted = true;
            return None;
        }

        let status = unsafe {
            FwpmFilterEnum0(
                self.tx.engine.as_raw_handle(),
                self.enum_handle,
                BATCH,
                &mut self.entries,
                &mut self.num_entries,
            )
        };
        self.index = 0;

        match status {
            ERROR_SUCCESS => {
                if self.num_entries == 0 {
                    self.exhausted = true;
                    return None;
                }
                // SAFETY: at least one entry; FilterEnumItem borrows self
                let filter = unsafe { &**self.entries };
                self.index = 1;
                Some(Ok(FilterEnumItem { filter, _enum: self }))
            }
            ERROR_NO_MORE_ITEMS => {
                self.exhausted = true;
                None
            }
            _ => {
                self.exhausted = true;
                Some(Err(io::Error::from_raw_os_error(status as i32)))
            }
        }
    }

    fn free_entries(&mut self) {
        if !self.entries.is_null() {
            // SAFETY: entries was allocated by FwpmFilterEnum0
            unsafe { FwpmFreeMemory0(&mut self.entries as *mut _ as *mut _) };
            self.entries = ptr::null_mut();
            self.num_entries = 0;
            self.index = 0;
        }
    }
}

impl Drop for FilterEnumerator<'_, '_> {
    fn drop(&mut self) {
        self.free_entries();
        // SAFETY: handle was created by FwpmFilterCreateEnumHandle0 and is still valid
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.tx.engine.as_raw_handle(), self.enum_handle);
        }
    }
}

/// A single WFP filter returned by `FilterEnumerator`.
pub struct FilterEnumItem<'a, 'b, 'c> {
    filter: &'c FWPM_FILTER0,
    _enum: &'c FilterEnumerator<'a, 'b>,
}

impl FilterEnumItem<'_, '_, '_> {
    /// Filter numeric ID.
    pub fn id(&self) -> u64 {
        self.filter.filterId
    }

    /// Filter GUID.
    pub fn guid(&self) -> windows_sys::core::GUID {
        self.filter.filterKey
    }

    /// Provider GUID, if set.
    pub fn provider(&self) -> Option<windows_sys::core::GUID> {
        if self.filter.providerKey.is_null() {
            None
        } else {
            // SAFETY: providerKey is non-null and points to a valid GUID
            Some(unsafe { *self.filter.providerKey })
        }
    }

    /// Filter display name, if set.
    pub fn name(&self) -> io::Result<Option<String>> {
        read_wstr(self.filter.displayData.name)
    }

    /// Filter description, if set.
    pub fn description(&self) -> io::Result<Option<String>> {
        read_wstr(self.filter.displayData.description)
    }

    /// The sublayer key this filter belongs to.
    pub fn sublayer(&self) -> windows_sys::core::GUID {
        self.filter.subLayerKey
    }
}

fn read_wstr(p: *const u16) -> io::Result<Option<String>> {
    if p.is_null() {
        return Ok(None);
    }
    // SAFETY: p is a null-terminated UTF-16 string owned by the WFP API
    let len = unsafe { wcslen(p) };
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16(slice)
        .map(Some)
        .map_err(|_| io::Error::other("invalid UTF-16"))
}

/// Length of null-terminated UTF-16 string.
///
/// # Safety
/// `s` must be null-terminated.
unsafe fn wcslen(s: *const u16) -> usize {
    let mut p = s;
    while unsafe { ptr::read_unaligned(p) } != 0 {
        p = unsafe { p.add(1) };
    }
    // SAFETY: p >= s
    (unsafe { p.offset_from(s) }) as usize
}
