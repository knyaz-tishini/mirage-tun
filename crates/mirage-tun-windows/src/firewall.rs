#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr};
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
}

impl WfpKillSwitch {
    pub fn new() -> Self {
        Self { engine: None, native_if_index: None }
    }

    pub fn set_native_if_index(&mut self, idx: u32) {
        self.native_if_index = Some(idx);
    }

    fn weight(n: u8) -> FilterWeight {
        // SAFETY: all call-sites pass literals 1, 13, 14, 15 which are <= 15.
        FilterWeight::Range(WeightRange::try_from(n).expect("weight value must be 0..=15"))
    }
}

fn resolve_interface_index(name: &str) -> Option<u32> {
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
        let tun_if_index = resolve_interface_index(tun_name);
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

            // 1. Block ALL outbound ConnectV4 (weight 1 = evaluated last).
            FilterBuilder::new()
                .name("Mirage: block all outbound")
                .action(Action::Block)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(1))
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("block-all filter failed: {e}")))?;

            // 2. Permit loopback 127.0.0.0/8 (weight 15 = evaluated first).
            FilterBuilder::new()
                .name("Mirage: permit loopback")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(15))
                .condition(AddrConditionBuilder::remote().subnet_v4(
                    u32::from(Ipv4Addr::new(127, 0, 0, 0)),
                    0xFF00_0000,
                ))
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("loopback permit failed: {e}")))?;

            // 3. Permit each relay IP (weight 14).
            for relay_addr in relay_addrs {
                if let IpAddr::V4(v4) = relay_addr {
                    FilterBuilder::new()
                        .name("Mirage: permit relay")
                        .action(Action::Permit)
                        .layer(Layer::ConnectV4)
                        .sublayer(KILLSWITCH_SUBLAYER_GUID)
                        .weight(Self::weight(14))
                        .condition(AddrConditionBuilder::remote().equal_v4(*v4))
                        .add(&tx)
                        .map_err(|e| TunError::Wfp(format!("relay permit {v4} failed: {e}")))?;
                    info!(%v4, "WFP: permit relay IP");
                }
            }

            // 4. Permit all traffic on TUN interface (weight 14) — fires before routing.
            if let Some(tun_idx) = tun_if_index {
                FilterBuilder::new()
                    .name("Mirage: permit TUN interface")
                    .action(Action::Permit)
                    .layer(Layer::ConnectV4)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(14))
                    .condition(InterfaceConditionBuilder::equal(tun_idx))
                    .add(&tx)
                    .map_err(|e| TunError::Wfp(format!("TUN interface permit failed: {e}")))?;
                info!(tun_idx, "WFP: permit TUN interface");
            }

            // 4b. Permit native interface for bypass traffic (weight 13).
            if let Some(native_idx) = self.native_if_index {
                FilterBuilder::new()
                    .name("Mirage: permit native interface (bypass)")
                    .action(Action::Permit)
                    .layer(Layer::ConnectV4)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(13))
                    .condition(InterfaceConditionBuilder::equal(native_idx))
                    .add(&tx)
                    .map_err(|e| TunError::Wfp(format!("native interface bypass permit failed: {e}")))?;
                info!(native_idx, "WFP: permit native interface (bypass)");
            }

            // 5. Permit exempt local ports — management API etc. (weight 13).
            for &port in exempt_ports {
                FilterBuilder::new()
                    .name("Mirage: permit exempt port")
                    .action(Action::Permit)
                    .layer(Layer::ConnectV4)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(13))
                    .condition(PortConditionBuilder::local().equal(port))
                    .add(&tx)
                    .map_err(|e| TunError::Wfp(format!("exempt port {port} failed: {e}")))?;
                info!(port, "WFP: permit exempt port");
            }

            tx.commit().map_err(|e| TunError::Wfp(format!("WFP commit failed: {e}")))?;
        }

        info!(relay_count = relay_addrs.len(), "WFP kill-switch activated");
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
