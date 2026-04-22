//! WFP filter condition builders.

use std::ffi::OsStr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_MATCH_GREATER, FWP_MATCH_GREATER_OR_EQUAL,
    FWP_MATCH_LESS, FWP_MATCH_LESS_OR_EQUAL, FWP_MATCH_RANGE, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0,
};
use windows_sys::core::GUID;

use crate::blob::{OwnedByteBlob, app_id_from_filename};

/// How the condition value is compared to network data.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchType {
    Equal = FWP_MATCH_EQUAL,
    Greater = FWP_MATCH_GREATER,
    Less = FWP_MATCH_LESS,
    GreaterOrEqual = FWP_MATCH_GREATER_OR_EQUAL,
    LessOrEqual = FWP_MATCH_LESS_OR_EQUAL,
    Range = FWP_MATCH_RANGE,
}

/// Which field in the network flow is inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionField {
    RemoteAddress,
    LocalAddress,
    RemotePort,
    LocalPort,
    Protocol,
    AppId,
    InterfaceIndex,
}

impl ConditionField {
    /// WFP GUID for this field.
    pub fn guid(&self) -> &GUID {
        match self {
            Self::RemoteAddress => &FWPM_CONDITION_IP_REMOTE_ADDRESS,
            Self::LocalAddress => &FWPM_CONDITION_IP_LOCAL_ADDRESS,
            Self::RemotePort => &FWPM_CONDITION_IP_REMOTE_PORT,
            Self::LocalPort => &FWPM_CONDITION_IP_LOCAL_PORT,
            Self::Protocol => &FWPM_CONDITION_IP_PROTOCOL,
            Self::AppId => &FWPM_CONDITION_ALE_APP_ID,
            Self::InterfaceIndex => &FWPM_CONDITION_INTERFACE_INDEX,
        }
    }
}

/// A built filter condition, ready to pass to `FilterBuilder::condition`.
#[derive(Clone)]
pub struct Condition {
    pub(crate) raw: FWPM_FILTER_CONDITION0,
    // Keeps heap-allocated data alive that raw.conditionValue points into.
    _storage: Arc<Storage>,
}

type Storage = Option<Box<dyn std::any::Any + Send>>;

// SAFETY: WFP condition data is read-only after construction.
unsafe impl Send for Condition {}
unsafe impl Sync for Condition {}

struct InnerBuilder {
    field: ConditionField,
    match_type: MatchType,
}

impl InnerBuilder {
    fn build_u32(self, val: u32) -> Condition {
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_UINT32;
        raw.conditionValue.Anonymous.uint32 = val;
        Condition { raw, _storage: Arc::new(None) }
    }

    fn build_u16(self, val: u16) -> Condition {
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_UINT16;
        raw.conditionValue.Anonymous.uint16 = val;
        Condition { raw, _storage: Arc::new(None) }
    }

    fn build_u8(self, val: u8) -> Condition {
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_UINT8;
        raw.conditionValue.Anonymous.uint8 = val;
        Condition { raw, _storage: Arc::new(None) }
    }

    fn build_v4_mask(self, addr: u32, mask: u32) -> Condition {
        let mut am = Box::new(FWP_V4_ADDR_AND_MASK { addr, mask });
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_V4_ADDR_MASK;
        // Points into am; am kept alive via storage.
        raw.conditionValue.Anonymous.v4AddrMask = &mut *am as *mut _;
        let storage: Storage = Some(am as Box<dyn std::any::Any + Send>);
        Condition { raw, _storage: Arc::new(storage) }
    }

    fn build_v6_mask(self, addr: Ipv6Addr, prefix_len: u8) -> Condition {
        let mut am = Box::new(FWP_V6_ADDR_AND_MASK {
            addr: addr.octets(),
            prefixLength: prefix_len,
        });
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_V6_ADDR_MASK;
        // Points into am; am kept alive via storage.
        raw.conditionValue.Anonymous.v6AddrMask = &mut *am as *mut _;
        let storage: Storage = Some(am as Box<dyn std::any::Any + Send>);
        Condition { raw, _storage: Arc::new(storage) }
    }

    fn build_blob(self, blob: OwnedByteBlob) -> Condition {
        let mut raw: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        raw.fieldKey = *self.field.guid();
        raw.matchType = self.match_type as i32;
        raw.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        // Points into blob; blob kept alive via storage.
        raw.conditionValue.Anonymous.byteBlob = blob.as_ptr() as _;
        let storage: Storage = Some(Box::new(blob) as Box<dyn std::any::Any + Send>);
        Condition { raw, _storage: Arc::new(storage) }
    }
}

// ── Port conditions ──────────────────────────────────────────────────────────

/// Builder for remote/local port conditions.
pub struct PortConditionBuilder {
    field: ConditionField,
}

impl PortConditionBuilder {
    /// Remote port condition.
    pub fn remote() -> Self {
        Self { field: ConditionField::RemotePort }
    }

    /// Local port condition.
    pub fn local() -> Self {
        Self { field: ConditionField::LocalPort }
    }

    /// Match exact port number.
    pub fn equal(self, port: u16) -> Condition {
        InnerBuilder { field: self.field, match_type: MatchType::Equal }.build_u16(port)
    }
}

// ── Protocol conditions ──────────────────────────────────────────────────────

/// Builder for IP protocol conditions.
pub struct ProtocolConditionBuilder;

impl ProtocolConditionBuilder {
    /// TCP (protocol 6).
    pub fn tcp() -> Condition {
        Self::proto(6)
    }

    /// UDP (protocol 17).
    pub fn udp() -> Condition {
        Self::proto(17)
    }

    /// ICMP (protocol 1).
    pub fn icmp() -> Condition {
        Self::proto(1)
    }

    /// Arbitrary protocol number.
    pub fn proto(n: u8) -> Condition {
        InnerBuilder { field: ConditionField::Protocol, match_type: MatchType::Equal }.build_u8(n)
    }
}

// ── Address conditions ───────────────────────────────────────────────────────

/// Builder for IPv4 address conditions (remote or local, exact or subnet).
pub struct AddrConditionBuilder {
    field: ConditionField,
}

impl AddrConditionBuilder {
    /// Remote address condition.
    pub fn remote() -> Self {
        Self { field: ConditionField::RemoteAddress }
    }

    /// Local address condition.
    pub fn local() -> Self {
        Self { field: ConditionField::LocalAddress }
    }

    /// Exact IPv4 address match.
    pub fn equal_v4(self, addr: Ipv4Addr) -> Condition {
        InnerBuilder { field: self.field, match_type: MatchType::Equal }
            .build_u32(u32::from(addr))
    }

    /// IPv4 subnet match (addr + mask, e.g. 127.0.0.0 / 0xFF000000 for /8).
    pub fn subnet_v4(self, addr: u32, mask: u32) -> Condition {
        InnerBuilder { field: self.field, match_type: MatchType::Equal }
            .build_v4_mask(addr, mask)
    }

    /// Exact IPv6 address match (equivalent to /128 prefix).
    pub fn equal_v6(self, addr: Ipv6Addr) -> Condition {
        InnerBuilder { field: self.field, match_type: MatchType::Equal }
            .build_v6_mask(addr, 128)
    }

    /// IPv6 prefix match (addr + prefix_len, e.g. ::1/128 for loopback).
    pub fn prefix_v6(self, addr: Ipv6Addr, prefix_len: u8) -> Condition {
        InnerBuilder { field: self.field, match_type: MatchType::Equal }
            .build_v6_mask(addr, prefix_len)
    }
}

// ── App ID conditions ────────────────────────────────────────────────────────

/// Builder for application-ID conditions.
pub struct AppIdConditionBuilder;

impl AppIdConditionBuilder {
    /// Match application by executable path.
    pub fn equal(path: impl AsRef<OsStr>) -> io::Result<Condition> {
        let blob = app_id_from_filename(path)?;
        Ok(InnerBuilder { field: ConditionField::AppId, match_type: MatchType::Equal }
            .build_blob(blob))
    }
}

// ── Interface index conditions ───────────────────────────────────────────────

/// Builder for network interface index conditions.
pub struct InterfaceConditionBuilder;

impl InterfaceConditionBuilder {
    /// Match exact interface index.
    pub fn equal(idx: u32) -> Condition {
        InnerBuilder { field: ConditionField::InterfaceIndex, match_type: MatchType::Equal }
            .build_u32(idx)
    }
}
