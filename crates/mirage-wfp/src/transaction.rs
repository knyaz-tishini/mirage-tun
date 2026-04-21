//! WFP transaction management.

use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};

use crate::engine::WfpEngine;

/// Atomic transaction over WFP filter operations. Drop aborts if not committed.
pub struct WfpTransaction<'a> {
    pub(crate) engine: &'a mut WfpEngine,
    committed: bool,
}

// SAFETY: safe to move between threads
unsafe impl Send for WfpTransaction<'_> {}

impl<'a> WfpTransaction<'a> {
    /// Begins a new transaction on the engine.
    pub fn begin(engine: &'a mut WfpEngine) -> io::Result<Self> {
        let status = unsafe { FwpmTransactionBegin0(engine.as_raw_handle(), 0) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self { engine, committed: false })
    }

    /// Commits all operations in this transaction.
    pub fn commit(mut self) -> io::Result<()> {
        let status = unsafe { FwpmTransactionCommit0(self.engine.as_raw_handle()) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        self.committed = true;
        Ok(())
    }

    /// Explicitly aborts, rolling back all operations.
    pub fn abort(mut self) -> io::Result<()> {
        self.committed = true; // prevent double-abort in Drop
        let status = unsafe { FwpmTransactionAbort0(self.engine.as_raw_handle()) };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

impl Drop for WfpTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let status = unsafe { FwpmTransactionAbort0(self.engine.as_raw_handle()) };
            if status != ERROR_SUCCESS {
                tracing::error!("WFP transaction abort on drop failed: {status:#X}");
            }
        }
    }
}
