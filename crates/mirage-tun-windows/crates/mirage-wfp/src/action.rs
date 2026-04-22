//! Filter action types.

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
};

/// Action taken when a filter matches traffic.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Allow matching traffic.
    Permit = FWP_ACTION_PERMIT,
    /// Drop matching traffic.
    Block = FWP_ACTION_BLOCK,
}
