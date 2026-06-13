#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, info, warn};
use mirage_wfp::{
    Action, AddrConditionBuilder, FilterBuilder, FilterEnumerator, FilterWeight,
    InterfaceConditionBuilder, Layer, PortConditionBuilder, SubLayerBuilder, WfpEngine,
    WfpTransaction, WeightRange, GUID, delete_filter,
};
use mirage_tun_core::traits::{PlatformFirewall, PlatformExecutor, FlowProto, FlowKey};
use mirage_tun_core::plane::{Plane, ProcessIdentity};
use mirage_tun_core::policy::ProcessInfo as CoreProcessInfo;
use mirage_tun_core::traits::private;
use crate::error::TunError;
use crate::process_info::ProcessResolver;

// Fixed GUID for our sublayer — deterministic so we don't leak sublayers on crash.
const KILLSWITCH_SUBLAYER_GUID: GUID = GUID::from_u128(0x4d697261_6765_4b69_6c6c_537769746368);

pub struct WfpKillSwitch {
    engine: Option<WfpEngine>,
    native_if_index: Option<u32>,
    tun_if_index: Option<u32>,
    /// Bypass CIDR list: (network_addr_be, mask) pairs for IPv4.
    bypass_cidrs: Vec<(u32, u32)>,
    /// Bypass CIDR list: (network_addr, mask) pairs for IPv6.
    bypass_cidrs_v6: Vec<(u128, u128)>,
    /// Process resolver for flow attribution (T2 addition — additive field).
    resolver: ProcessResolver,
}

impl WfpKillSwitch {
    pub fn new() -> Self {
        Self {
            engine: None,
            native_if_index: None,
            tun_if_index: None,
            bypass_cidrs: Vec::new(),
            bypass_cidrs_v6: Vec::new(),
            resolver: ProcessResolver::new(),
        }
    }

    pub fn set_native_if_index(&mut self, idx: u32) {
        self.native_if_index = Some(idx);
    }

    /// Pre-set the TUN interface index so `activate` does not need to spawn a
    /// subprocess. Call this (via `spawn_blocking`) before holding any async mutex.
    pub fn set_tun_if_index(&mut self, idx: u32) {
        self.tun_if_index = Some(idx);
    }

    /// Set bypass CIDRs to be permitted by WFP at weight 12.
    /// Each entry is (network_addr_u32_host_order, mask_u32).
    pub fn set_bypass_cidrs(&mut self, cidrs: Vec<(u32, u32)>) {
        self.bypass_cidrs = cidrs;
    }

    /// Set bypass CIDRs to be permitted by WFP at weight 12 (IPv6).
    /// Each entry is (network_addr_u128, mask_u128).
    pub fn set_bypass_cidrs_v6(&mut self, cidrs: Vec<(u128, u128)>) {
        self.bypass_cidrs_v6 = cidrs;
    }

    /// Re-apply WFP filters with an updated bypass CIDR list (IPv4 + IPv6).
    /// Deactivates the current engine and re-activates with the new CIDRs.
    pub fn update_bypass_cidrs(
        &mut self,
        cidrs: Vec<(u32, u32)>,
        cidrs_v6: Vec<(u128, u128)>,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        self.bypass_cidrs = cidrs;
        self.bypass_cidrs_v6 = cidrs_v6;
        // activate already runs stale-filter cleanup before installing new filters,
        // so calling it directly is sufficient; deactivate first is not required.
        self.activate(relay_addrs, tun_name, exempt_ports)
    }

    fn weight(n: u8) -> FilterWeight {
        // SAFETY: all call-sites pass literals 1, 12, 13, 14, 15 which are <= 15.
        FilterWeight::Range(WeightRange::try_from(n).expect("weight value must be 0..=15"))
    }

    fn install_v4_filters(
        &self,
        tx: &WfpTransaction,
        relay_addrs: &[IpAddr],
        tun_if_index: Option<u32>,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        // 1. Block ALL outbound ConnectV4 (weight 1 = evaluated last).
        FilterBuilder::new()
            .name("Mirage: block all outbound IPv4")
            .action(Action::Block)
            .layer(Layer::ConnectV4)
            .sublayer(KILLSWITCH_SUBLAYER_GUID)
            .weight(Self::weight(1))
            .add(tx)
            .map_err(|e| TunError::Wfp(format!("block-all IPv4 filter failed: {e}")))?;

        // 2. Permit loopback 127.0.0.0/8 (weight 15 = evaluated first).
        FilterBuilder::new()
            .name("Mirage: permit loopback IPv4")
            .action(Action::Permit)
            .layer(Layer::ConnectV4)
            .sublayer(KILLSWITCH_SUBLAYER_GUID)
            .weight(Self::weight(15))
            .condition(AddrConditionBuilder::remote().subnet_v4(
                u32::from(Ipv4Addr::new(127, 0, 0, 0)),
                0xFF00_0000,
            ))
            .add(tx)
            .map_err(|e| TunError::Wfp(format!("loopback IPv4 permit failed: {e}")))?;

        // 3. Permit each relay IPv4 (weight 14).
        for relay_addr in relay_addrs {
            if let IpAddr::V4(v4) = relay_addr {
                FilterBuilder::new()
                    .name("Mirage: permit relay IPv4")
                    .action(Action::Permit)
                    .layer(Layer::ConnectV4)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(14))
                    .condition(AddrConditionBuilder::remote().equal_v4(*v4))
                    .add(tx)
                    .map_err(|e| TunError::Wfp(format!("relay permit {v4} failed: {e}")))?;
                info!(%v4, "WFP: permit relay IPv4");
            }
        }

        // 4. Permit all traffic on TUN interface (weight 14) — fires before routing.
        if let Some(tun_idx) = tun_if_index {
            FilterBuilder::new()
                .name("Mirage: permit TUN interface IPv4")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(14))
                .condition(InterfaceConditionBuilder::equal(tun_idx))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("TUN interface IPv4 permit failed: {e}")))?;
            info!(tun_idx, "WFP: permit TUN interface IPv4");
        }

        // 4b. Permit native interface for bypass traffic (weight 13).
        if let Some(native_idx) = self.native_if_index {
            FilterBuilder::new()
                .name("Mirage: permit native interface IPv4 (bypass)")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(13))
                .condition(InterfaceConditionBuilder::equal(native_idx))
                .add(tx)
                .map_err(|e| {
                    TunError::Wfp(format!("native interface IPv4 bypass permit failed: {e}"))
                })?;
            info!(native_idx, "WFP: permit native interface IPv4 (bypass)");
        }

        // 5. Permit bypass CIDRs (weight 12).
        for &(network, mask) in &self.bypass_cidrs {
            FilterBuilder::new()
                .name("Mirage: permit bypass CIDR")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(12))
                .condition(AddrConditionBuilder::remote().subnet_v4(network, mask))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("bypass CIDR permit failed: {e}")))?;
            let net_ip = Ipv4Addr::from(network);
            let mask_ip = Ipv4Addr::from(mask);
            info!(%net_ip, %mask_ip, "WFP: permit bypass CIDR");
        }

        // 6. Permit exempt local ports (weight 13).
        for &port in exempt_ports {
            FilterBuilder::new()
                .name("Mirage: permit exempt port")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(13))
                .condition(PortConditionBuilder::local().equal(port))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("exempt port {port} failed: {e}")))?;
            info!(port, "WFP: permit exempt port IPv4");
        }

        Ok(())
    }

    fn install_v6_filters(
        &self,
        tx: &WfpTransaction,
        relay_addrs: &[IpAddr],
        tun_if_index: Option<u32>,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        // 1. Block ALL outbound ConnectV6 (weight 1 = evaluated last).
        FilterBuilder::new()
            .name("Mirage: block all outbound IPv6")
            .action(Action::Block)
            .layer(Layer::ConnectV6)
            .sublayer(KILLSWITCH_SUBLAYER_GUID)
            .weight(Self::weight(1))
            .add(tx)
            .map_err(|e| TunError::Wfp(format!("block-all IPv6 filter failed: {e}")))?;

        // 2. Permit loopback ::1/128 (weight 15).
        FilterBuilder::new()
            .name("Mirage: permit loopback IPv6")
            .action(Action::Permit)
            .layer(Layer::ConnectV6)
            .sublayer(KILLSWITCH_SUBLAYER_GUID)
            .weight(Self::weight(15))
            .condition(AddrConditionBuilder::remote().equal_v6(Ipv6Addr::LOCALHOST))
            .add(tx)
            .map_err(|e| TunError::Wfp(format!("loopback IPv6 permit failed: {e}")))?;

        // 3. Permit each relay IPv6 (weight 14).
        for relay_addr in relay_addrs {
            if let IpAddr::V6(v6) = relay_addr {
                FilterBuilder::new()
                    .name("Mirage: permit relay IPv6")
                    .action(Action::Permit)
                    .layer(Layer::ConnectV6)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(14))
                    .condition(AddrConditionBuilder::remote().equal_v6(*v6))
                    .add(tx)
                    .map_err(|e| TunError::Wfp(format!("relay permit {v6} failed: {e}")))?;
                info!(%v6, "WFP: permit relay IPv6");
            }
        }

        // 4. Permit all traffic on TUN interface (weight 14).
        if let Some(tun_idx) = tun_if_index {
            FilterBuilder::new()
                .name("Mirage: permit TUN interface IPv6")
                .action(Action::Permit)
                .layer(Layer::ConnectV6)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(14))
                .condition(InterfaceConditionBuilder::equal(tun_idx))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("TUN interface IPv6 permit failed: {e}")))?;
            info!(tun_idx, "WFP: permit TUN interface IPv6");
        }

        // 4b. Permit native interface for bypass traffic (weight 13).
        if let Some(native_idx) = self.native_if_index {
            FilterBuilder::new()
                .name("Mirage: permit native interface IPv6 (bypass)")
                .action(Action::Permit)
                .layer(Layer::ConnectV6)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(13))
                .condition(InterfaceConditionBuilder::equal(native_idx))
                .add(tx)
                .map_err(|e| {
                    TunError::Wfp(format!("native interface IPv6 bypass permit failed: {e}"))
                })?;
            info!(native_idx, "WFP: permit native interface IPv6 (bypass)");
        }

        // 5. Permit exempt local ports (weight 13).
        for &port in exempt_ports {
            FilterBuilder::new()
                .name("Mirage: permit exempt port IPv6")
                .action(Action::Permit)
                .layer(Layer::ConnectV6)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(13))
                .condition(PortConditionBuilder::local().equal(port))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("exempt port {port} IPv6 failed: {e}")))?;
            info!(port, "WFP: permit exempt port IPv6");
        }

        // 6. Permit bypass CIDRs for IPv6 (weight 12).
        for &(network, mask) in &self.bypass_cidrs_v6 {
            let prefix_len = mask.count_ones() as u8;
            let addr = Ipv6Addr::from(network);
            FilterBuilder::new()
                .name("Mirage: permit bypass CIDR IPv6")
                .action(Action::Permit)
                .layer(Layer::ConnectV6)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(12))
                .condition(AddrConditionBuilder::remote().prefix_v6(addr, prefix_len))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("bypass CIDR IPv6 permit {addr}/{prefix_len} failed: {e}")))?;
            info!(%addr, prefix_len, "WFP: permit bypass CIDR IPv6");
        }

        Ok(())
    }
}

pub fn resolve_interface_index(name: &str) -> Option<u32> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(name) || trimmed.contains(&format!(" {name}")) {
            let idx_str = trimmed.split_whitespace().next()?;
            return idx_str.parse().ok();
        }
    }
    None
}

/// Compare two WFP GUIDs for equality.
///
/// `windows_sys::core::GUID` does not implement `PartialEq` in all versions;
/// compare the constituent fields directly.
fn guid_eq(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

impl WfpKillSwitch {
    /// Best-effort deletion of all kill-switch filters via a fresh persistent session.
    /// Always opens a new session so there are no borrow issues with `self.engine`.
    /// Errors are logged as warnings and swallowed — cleanup must never panic.
    fn remove_killswitch_filters_best_effort() {
        match WfpEngine::open() {
            Ok(mut engine) => {
                if let Err(e) = Self::delete_killswitch_filters(&mut engine) {
                    warn!("WFP: filter cleanup error (best-effort): {e}");
                }
            }
            Err(e) => {
                warn!("WFP: could not open engine for filter cleanup: {e}");
            }
        }
    }

    fn delete_killswitch_filters(engine: &mut WfpEngine) -> Result<(), std::io::Error> {
        let tx = WfpTransaction::begin(engine)
            .map_err(|e| std::io::Error::other(format!("tx begin: {e}")))?;

        let stale_ids: Vec<u64> = {
            let mut enumerator = FilterEnumerator::new(&tx)?;
            let mut ids = Vec::new();
            while let Some(result) = enumerator.next() {
                let item = result?;
                if guid_eq(item.sublayer(), KILLSWITCH_SUBLAYER_GUID) {
                    ids.push(item.id());
                }
            }
            ids
        };

        for id in stale_ids {
            delete_filter(&tx, id)?;
        }

        tx.commit().map_err(|e| std::io::Error::other(format!("tx commit: {e}")))?;
        Ok(())
    }
}

impl PlatformFirewall for WfpKillSwitch {
    type Error = TunError;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        // Use pre-resolved index if caller set it via `set_tun_if_index`, otherwise
        // fall back to the blocking subprocess (should only happen in tests or when
        // called outside an async context).
        let tun_if_index = self.tun_if_index.or_else(|| resolve_interface_index(tun_name));
        info!(tun_name, ?tun_if_index, "WFP: resolved TUN interface index");

        // Open a persistent session — filters survive engine drop and process crash,
        // ensuring fail-closed behaviour. Filters do NOT survive a reboot because we
        // do not set FWPM_FILTER_FLAG_PERSISTENT or FWPM_FILTER_FLAG_BOOTTIME.
        let mut engine = WfpEngine::open().map_err(|e| {
            TunError::Wfp(format!("WFP engine open failed: {e}"))
        })?;

        {
            let tx = WfpTransaction::begin(&mut engine).map_err(|e| {
                TunError::Wfp(format!("WFP transaction begin failed: {e}"))
            })?;

            // Add our sublayer. On a persistent session a previous run may have left
            // it behind; FWP_E_ALREADY_EXISTS (0x80320009) is not an error here.
            match SubLayerBuilder::default()
                .name("Mirage Kill-switch")
                .description("Blocks traffic leaks when TUN active")
                .guid(KILLSWITCH_SUBLAYER_GUID)
                .weight(100)
                .add(&tx)
            {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(0x80320009u32 as i32) => {
                    debug!("WFP: kill-switch sublayer already exists — reusing");
                }
                Err(e) => return Err(TunError::Wfp(format!("sublayer add failed: {e}"))),
            }

            // Remove any stale filters from a previous run (crashed or clean).
            // Collect IDs first to avoid a simultaneous borrow of `tx`.
            let stale_ids: Vec<u64> = {
                let mut enumerator = FilterEnumerator::new(&tx)
                    .map_err(|e| TunError::Wfp(format!("filter enumerator failed: {e}")))?;
                let mut ids = Vec::new();
                while let Some(result) = enumerator.next() {
                    let item = result
                        .map_err(|e| TunError::Wfp(format!("filter enumeration error: {e}")))?;
                    if guid_eq(item.sublayer(), KILLSWITCH_SUBLAYER_GUID) {
                        ids.push(item.id());
                    }
                }
                ids
            };
            for id in stale_ids {
                delete_filter(&tx, id)
                    .map_err(|e| TunError::Wfp(format!("stale filter delete failed: {e}")))?;
            }
            debug!("WFP: stale kill-switch filters removed");

            self.install_v4_filters(&tx, relay_addrs, tun_if_index, exempt_ports)?;
            self.install_v6_filters(&tx, relay_addrs, tun_if_index, exempt_ports)?;

            tx.commit().map_err(|e| TunError::Wfp(format!("WFP commit failed: {e}")))?;
        }

        info!(relay_count = relay_addrs.len(), "WFP kill-switch activated (IPv4 + IPv6)");
        self.engine = Some(engine);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), TunError> {
        Self::remove_killswitch_filters_best_effort();
        self.engine.take();
        info!("WFP kill-switch deactivated — filters removed");
        Ok(())
    }
}

impl Drop for WfpKillSwitch {
    fn drop(&mut self) {
        // On a clean drop (e.g. forgot to call deactivate), remove our filters so
        // they don't linger. On a process CRASH, Drop does NOT run → filters persist
        // in the kernel → that is the intended fail-closed behaviour.
        if self.engine.is_some() {
            warn!("WfpKillSwitch dropped while active — removing filters");
            Self::remove_killswitch_filters_best_effort();
            self.engine.take();
        }
    }
}

// ── T2: PlatformExecutor impl ─────────────────────────────────────────────────

impl private::Sealed for WfpKillSwitch {}

/// Convert the Windows-local `ProcessInfo` (from `process_info.rs`) to the core type.
/// The two structs are structurally identical — this is a name-only conversion.
/// T3 will delete `mirage-tun-windows/src/policy.rs` and unify the types.
fn local_info_to_core(info: crate::process_info::ProcessInfo) -> CoreProcessInfo {
    CoreProcessInfo {
        pid: info.pid,
        exe_path: info.exe_path,
        ancestor_paths: info.ancestor_paths,
    }
}

impl PlatformExecutor for WfpKillSwitch {
    type Error = TunError;

    /// Attribute a flow to a `ProcessIdentity` using the existing `ProcessResolver`.
    ///
    /// For TCP: uses `resolver.resolve(src_port, dst)`.
    /// For UDP: uses `resolver.resolve_udp(src_port)`.
    /// Must be called from a `spawn_blocking` context — Win32 synchronous APIs.
    ///
    /// For T2: attribution is returned without a `platform_token` (WFP app-id blob
    /// attachment is T3). T3 will attach the FWP_BYTE_BLOB app-id here.
    fn attribute(
        &self,
        src_port: u16,
        dst: std::net::SocketAddr,
        proto: FlowProto,
    ) -> Option<ProcessIdentity> {
        let local_info = match proto {
            FlowProto::Tcp => self.resolver.resolve(src_port, dst)?,
            FlowProto::Udp => self.resolver.resolve_udp(src_port)?,
        };
        Some(ProcessIdentity::from_process_info(local_info_to_core(local_info)))
    }

    /// Enforce the plane decision.
    ///
    /// T2: coarse enforcement — the existing WFP sublayer already handles
    /// block/permit at interface granularity via `activate()`. Per-process
    /// WFP app-id conditions are T3. The only invalid call is `Plane::Group`
    /// (caller must resolve it before calling enforce).
    fn enforce(
        &mut self,
        plane: &Plane,
        _identity: Option<&ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), TunError> {
        match plane {
            Plane::Group(_) => {
                tracing::error!(?flow, "enforce called with unresolved Group plane — bug in caller");
                Err(TunError::Other("unresolved Group plane in enforce".into()))
            }
            // T2: Bypass / Wire / Kill are all handled coarsely by the existing
            // WFP sublayer activated via activate(). No per-flow action needed.
            _ => Ok(()),
        }
    }
}
