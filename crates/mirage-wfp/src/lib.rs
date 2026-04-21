//! Mirage WFP — Windows Filtering Platform wrapper.
//!
//! Safe Rust interface for WFP filters, sublayers, and transactions.
//!
//! ```no_run
//! use mirage_wfp::*;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut engine = WfpEngine::open_dynamic()?;
//! let tx = WfpTransaction::begin(&mut engine)?;
//! add_sublayer(&tx, "Kill-switch", "", windows_sys::core::GUID::zeroed(), 100)?;
//! FilterBuilder::new()
//!     .name("Block all")
//!     .action(Action::Block)
//!     .layer(Layer::ConnectV4)
//!     .add(&tx)?;
//! tx.commit()?;
//! # Ok(()) }
//! ```

#![cfg(target_os = "windows")]

mod action;
mod blob;
mod condition;
mod engine;
mod enumerator;
mod filter;
mod layer;
mod sublayer;
mod transaction;
mod weight;

pub use action::Action;
pub use blob::{OwnedByteBlob, app_id_from_filename};
pub use condition::{
    AddrConditionBuilder, AppIdConditionBuilder, Condition, ConditionField, InterfaceConditionBuilder,
    MatchType, PortConditionBuilder, ProtocolConditionBuilder,
};
pub use engine::WfpEngine;
pub use enumerator::{FilterEnumItem, FilterEnumerator};
pub use filter::{FilterBuilder, FilterLifetime, delete_filter, delete_filter_by_guid};
pub use layer::Layer;
pub use sublayer::{SubLayerBuilder, add_sublayer};
pub use transaction::WfpTransaction;
pub use weight::{FilterWeight, WeightRange, WeightRangeError};

pub use windows_sys::core::GUID;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn to_wide_null(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}
