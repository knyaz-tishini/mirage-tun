#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};
use mirage_wfp::{
    Action, AddrConditionBuilder, FilterBuilder, FilterWeight, InterfaceConditionBuilder,
    Layer, PortConditionBuilder, SubLayerBuilder, WfpEngine, WfpTransaction, WeightRange, GUID,
};
use mirage_tun_core::traits::PlatformFirewall;
use crate::error::TunError;

// Fixed GUID for our sublayer — deterministic so we don't leak sublayers on crash.
const KILLSWITCH_SUBLAYER_GUID: GUID = GUID::from_u128(0x4d697261_6765_4b69_6c6c_537769746368);

pub struct WfpKillSwitch {
    engine: Option<WfpEngine>,
    native_if_index: Option<u32>,
    tun_if_index: Option<u32>,
    /// Bypass CIDR list: (network_addr_be, mask) pairs for IPv4.
    bypass_cidrs: Vec<(u32, u32)>,
}

impl WfpKillSwitch {
    pub fn new() -> Self {
        Self { engine: None, native_if_index: None, tun_if_index: None, bypass_cidrs: Vec::new() }
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

    /// Re-apply WFP filters with an updated bypass CIDR list.
    /// Deactivates the current engine and re-activates with the new CIDRs.
    pub fn update_bypass_cidrs(
        &mut self,
        cidrs: Vec<(u32, u32)>,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        self.bypass_cidrs = cidrs;
        // deactivate drops old engine (removes all filters), then re-activate.
        self.engine.take();
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

        // Drop old engine first — removes all previously installed dynamic filters.
        self.engine.take();

        let mut engine = WfpEngine::open_dynamic().map_err(|e| {
            TunError::Wfp(format!("WFP engine open failed: {e}"))
        })?;

        {
            let tx = WfpTransaction::begin(&mut engine).map_err(|e| {
                TunError::Wfp(format!("WFP transaction begin failed: {e}"))
            })?;

            // Add our sublayer — ignore "already exists" on a clean dynamic session.
            SubLayerBuilder::default()
                .name("Mirage Kill-switch")
                .description("Blocks traffic leaks when TUN active")
                .guid(KILLSWITCH_SUBLAYER_GUID)
                .weight(100)
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("sublayer add failed: {e}")))?;

            self.install_v4_filters(&tx, relay_addrs, tun_if_index, exempt_ports)?;
            self.install_v6_filters(&tx, relay_addrs, tun_if_index, exempt_ports)?;

            tx.commit().map_err(|e| TunError::Wfp(format!("WFP commit failed: {e}")))?;
        }

        info!(relay_count = relay_addrs.len(), "WFP kill-switch activated (IPv4 + IPv6)");
        self.engine = Some(engine);
        Ok(())
    }

    fn deactivate(&mut self) -> Result<(), TunError> {
        if self.engine.take().is_some() {
            info!("WFP kill-switch deactivated (dynamic filters removed)");
        }
        Ok(())
    }
}

impl Drop for WfpKillSwitch {
    fn drop(&mut self) {
        if self.engine.is_some() {
            warn!("WfpKillSwitch dropped while active — filters will be removed");
        }
    }
}
