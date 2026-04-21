//! WFP sublayer creation.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0, FwpmSubLayerAdd0,
};
use windows_sys::core::GUID;

use crate::to_wide_null;
use crate::transaction::WfpTransaction;

/// Type-state: name not set.
pub struct MissingName;
/// Type-state: name set.
pub struct HasName;

/// Builder for WFP sublayers.
#[derive(Clone)]
pub struct SubLayerBuilder<N> {
    guid: GUID,
    weight: u16,
    name_buf: Arc<Vec<u16>>,
    desc_buf: Arc<Vec<u16>>,
    _state: std::marker::PhantomData<N>,
}

impl Default for SubLayerBuilder<MissingName> {
    fn default() -> Self {
        Self {
            guid: GUID::from_u128(0),
            weight: 0,
            name_buf: Arc::new(Vec::new()),
            desc_buf: Arc::new(Vec::new()),
            _state: std::marker::PhantomData,
        }
    }
}

impl<N> SubLayerBuilder<N> {
    /// Set display name (required).
    pub fn name(self, name: &str) -> SubLayerBuilder<HasName> {
        SubLayerBuilder {
            guid: self.guid,
            weight: self.weight,
            name_buf: Arc::new(to_wide_null(name)),
            desc_buf: self.desc_buf,
            _state: std::marker::PhantomData,
        }
    }

    /// Set description.
    pub fn description(mut self, desc: &str) -> Self {
        self.desc_buf = Arc::new(to_wide_null(desc));
        self
    }

    /// Set priority weight.
    pub fn weight(mut self, w: u16) -> Self {
        self.weight = w;
        self
    }

    /// Set sublayer GUID (auto-assigned if zeroed).
    pub fn guid(mut self, guid: GUID) -> Self {
        self.guid = guid;
        self
    }
}

impl SubLayerBuilder<HasName> {
    /// Add this sublayer via transaction.
    pub fn add(&self, tx: &WfpTransaction<'_>) -> io::Result<()> {
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: self.guid,
            displayData: FWPM_DISPLAY_DATA0 {
                name: self.name_buf.as_ptr() as *mut _,
                description: if self.desc_buf.is_empty() {
                    ptr::null_mut()
                } else {
                    self.desc_buf.as_ptr() as *mut _
                },
            },
            weight: self.weight,
            ..unsafe { std::mem::zeroed() }
        };
        let status = unsafe {
            FwpmSubLayerAdd0(tx.engine.as_raw_handle(), &sublayer, ptr::null_mut())
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        tracing::debug!(name = ?String::from_utf16_lossy(&self.name_buf), "WFP sublayer added");
        Ok(())
    }
}

/// Convenience function — add a sublayer in one call.
pub fn add_sublayer(
    tx: &WfpTransaction<'_>,
    name: &str,
    description: &str,
    guid: GUID,
    weight: u16,
) -> io::Result<()> {
    SubLayerBuilder::default()
        .name(name)
        .description(description)
        .guid(guid)
        .weight(weight)
        .add(tx)
}
