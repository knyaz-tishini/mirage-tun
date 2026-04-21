#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr};
use tracing::{info, warn};
use mirage_wfp::{
    Action, AddrConditionBuilder, FilterBuilder, FilterWeight, Layer,
    PortConditionBuilder, SubLayerBuilder, WfpEngine, WfpTransaction, WeightRange, GUID,
};
use mirage_tun_core::traits::PlatformFirewall;
use crate::error::TunError;

// Fixed GUID for our sublayer — deterministic so we don't leak sublayers on crash.
const KILLSWITCH_SUBLAYER_GUID: GUID = GUID::from_u128(0x4d697261_6765_4b69_6c6c_537769746368);

pub struct WfpKillSwitch {
    engine: Option<WfpEngine>,
}

impl WfpKillSwitch {
    pub fn new() -> Self {
        Self { engine: None }
    }

    fn weight(n: u8) -> FilterWeight {
        // SAFETY: all call-sites pass literals 1, 13, 14, 15 which are <= 15.
        FilterWeight::Range(WeightRange::try_from(n).expect("weight value must be 0..=15"))
    }
}

impl PlatformFirewall for WfpKillSwitch {
    type Error = TunError;

    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        _tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
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

            // 4. Permit exempt local ports — management API etc. (weight 13).
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
