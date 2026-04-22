//! WFP filter creation and deletion.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_EMPTY, FWP_UINT8, FWP_UINT64, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_PERSISTENT, FwpmFilterAdd0,
    FwpmFilterDeleteById0, FwpmFilterDeleteByKey0,
};
use windows_sys::core::GUID;

use crate::action::Action;
use crate::condition::Condition;
use crate::layer::Layer;
use crate::to_wide_null;
use crate::transaction::WfpTransaction;
use crate::weight::FilterWeight;

/// Lifetime of a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterLifetime {
    /// Session lifetime (default).
    #[default]
    Default,
    /// Active only during boot (before BFE starts).
    Boottime,
    /// Persists across reboots.
    Persistent,
}

// Type-state markers.
pub struct MissingName;
pub struct HasName;
pub struct MissingAction;
pub struct HasAction;

/// Builder for WFP filters.
pub struct FilterBuilder<N, A> {
    name_buf: Arc<Vec<u16>>,
    desc_buf: Arc<Vec<u16>>,
    layer: Option<Layer>,
    sublayer: Option<GUID>,
    action: Option<Action>,
    weight: FilterWeight,
    weight_exact: u64,
    lifetime: FilterLifetime,
    guid: GUID,
    conditions: Vec<Condition>,
    _state: std::marker::PhantomData<(N, A)>,
}

impl Default for FilterBuilder<MissingName, MissingAction> {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterBuilder<MissingName, MissingAction> {
    /// Create a new filter builder.
    pub fn new() -> Self {
        Self {
            name_buf: Arc::new(Vec::new()),
            desc_buf: Arc::new(Vec::new()),
            layer: None,
            sublayer: None,
            action: None,
            weight: FilterWeight::Auto,
            weight_exact: 0,
            lifetime: FilterLifetime::Default,
            guid: GUID::from_u128(0),
            conditions: Vec::new(),
            _state: std::marker::PhantomData,
        }
    }
}

impl<N, A> FilterBuilder<N, A> {
    /// Set display name (required).
    pub fn name(self, name: &str) -> FilterBuilder<HasName, A> {
        FilterBuilder {
            name_buf: Arc::new(to_wide_null(name)),
            desc_buf: self.desc_buf,
            layer: self.layer,
            sublayer: self.sublayer,
            action: self.action,
            weight: self.weight,
            weight_exact: self.weight_exact,
            lifetime: self.lifetime,
            guid: self.guid,
            conditions: self.conditions,
            _state: std::marker::PhantomData,
        }
    }

    /// Set description.
    pub fn description(mut self, desc: &str) -> Self {
        self.desc_buf = Arc::new(to_wide_null(desc));
        self
    }

    /// Set action (required).
    pub fn action(self, action: Action) -> FilterBuilder<N, HasAction> {
        FilterBuilder {
            name_buf: self.name_buf,
            desc_buf: self.desc_buf,
            layer: self.layer,
            sublayer: self.sublayer,
            action: Some(action),
            weight: self.weight,
            weight_exact: self.weight_exact,
            lifetime: self.lifetime,
            guid: self.guid,
            conditions: self.conditions,
            _state: std::marker::PhantomData,
        }
    }

    /// Set layer.
    pub fn layer(mut self, layer: Layer) -> Self {
        self.layer = Some(layer);
        self
    }

    /// Set sublayer GUID.
    pub fn sublayer(mut self, guid: GUID) -> Self {
        self.sublayer = Some(guid);
        self
    }

    /// Set weight.
    pub fn weight(mut self, w: impl Into<FilterWeight>) -> Self {
        let fw = w.into();
        if let FilterWeight::Exact(v) = fw {
            self.weight_exact = v;
        }
        self.weight = fw;
        self
    }

    /// Set filter lifetime.
    pub fn lifetime(mut self, lt: FilterLifetime) -> Self {
        self.lifetime = lt;
        self
    }

    /// Set filter GUID (auto-assigned if zeroed).
    pub fn guid(mut self, guid: GUID) -> Self {
        self.guid = guid;
        self
    }

    /// Add a condition (all conditions ANDed; same-field conditions ORed by WFP).
    pub fn condition(mut self, c: Condition) -> Self {
        self.conditions.push(c);
        self
    }
}

impl FilterBuilder<HasName, HasAction> {
    /// Add this filter to the engine via transaction. Returns filter ID.
    pub fn add(&self, tx: &WfpTransaction<'_>) -> io::Result<u64> {
        let raw_conds: Vec<FWPM_FILTER_CONDITION0> =
            self.conditions.iter().map(|c| c.raw).collect();

        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.filterKey = self.guid;
        filter.displayData.name = self.name_buf.as_ptr() as *mut _;
        if !self.desc_buf.is_empty() {
            filter.displayData.description = self.desc_buf.as_ptr() as *mut _;
        }
        if let Some(layer) = self.layer {
            filter.layerKey = *layer.guid();
        }
        if let Some(sublayer) = self.sublayer {
            filter.subLayerKey = sublayer;
        }
        filter.action.r#type = self.action.expect("HasAction guarantees Some") as u32;

        // Lifetime flags
        filter.flags &= !(FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_PERSISTENT);
        match self.lifetime {
            FilterLifetime::Default => {}
            FilterLifetime::Boottime => filter.flags |= FWPM_FILTER_FLAG_BOOTTIME,
            FilterLifetime::Persistent => filter.flags |= FWPM_FILTER_FLAG_PERSISTENT,
        }

        // Weight
        match self.weight {
            FilterWeight::Auto => filter.weight.r#type = FWP_EMPTY,
            FilterWeight::Range(r) => {
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = r.get();
            }
            FilterWeight::Exact(_) => {
                // Pointer must be set here after all moves complete.
                filter.weight.r#type = FWP_UINT64;
                filter.weight.Anonymous.uint64 = &self.weight_exact as *const u64 as *mut u64;
            }
        }

        // Conditions
        if !raw_conds.is_empty() {
            filter.numFilterConditions = raw_conds.len() as u32;
            filter.filterCondition = raw_conds.as_ptr() as *mut _;
        }

        let mut id: u64 = 0;
        let status = unsafe {
            FwpmFilterAdd0(
                tx.engine.as_raw_handle(),
                &filter,
                ptr::null_mut(),
                &mut id,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(id)
    }
}

/// Delete a filter by its numeric ID.
pub fn delete_filter(tx: &WfpTransaction<'_>, id: u64) -> io::Result<()> {
    let status = unsafe { FwpmFilterDeleteById0(tx.engine.as_raw_handle(), id) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Delete a filter by its GUID.
pub fn delete_filter_by_guid(tx: &WfpTransaction<'_>, guid: &GUID) -> io::Result<()> {
    let status = unsafe { FwpmFilterDeleteByKey0(tx.engine.as_raw_handle(), guid) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
