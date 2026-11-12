#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;

use mirage_wfp::{
    Action, AddrConditionBuilder, AppIdConditionBuilder, FilterBuilder, FilterEnumerator,
    FilterWeight, FlagsConditionBuilder, InterfaceConditionBuilder, Layer, OwnedByteBlob,
    PortConditionBuilder, SubLayerBuilder, WfpEngine, WfpTransaction, WeightRange, GUID,
    FLAG_IS_RAW_ENDPOINT, delete_filter,
};
use mirage_tun_core::traits::{PlatformFirewall, PlatformExecutor, FlowProto, FlowKey};
use mirage_tun_core::plane::{Plane, ProcessIdentity};
use mirage_tun_core::traits::private;
use crate::error::TunError;
use crate::process_info::ProcessResolver;

// Fixed GUID for our sublayer — deterministic so we don't leak sublayers on crash.
const KILLSWITCH_SUBLAYER_GUID: GUID = GUID::from_u128(0x4d697261_6765_4b69_6c6c_537769746368);

/// The permits of the applications that leave the tunnel.
///
/// Every filter of the switch is filed under the application it belongs to:
/// the filters of the switch survive the run (the session is persistent),
/// so a permit that is not taken away stays for ever.  An application that
/// was let out of the tunnel once would then keep working around it for
/// ever -- and the person who took it off the list would never see the
/// tunnel again.
#[derive(Debug, Default)]
struct AppPermits {
    /// The key of the application -> the ids of its filters.
    filters: BTreeMap<String, Vec<u64>>,
}

/// The key a path of an application is filed under.
///
/// The same path in two spellings ("C:/a/b.exe" and "C:\a\b.exe") is the
/// same application, and the case of the letters does not matter on
/// Windows.
fn permit_key(path: &str) -> String {
    path.trim().replace('/', "\\").to_ascii_lowercase()
}

impl AppPermits {
    /// The filters of the applications that are not on the list any more.
    ///
    /// These are the permits that have to be taken away: the application
    /// goes back into the tunnel.
    fn stale(&self, wanted: &[String]) -> Vec<(String, Vec<u64>)> {
        let keys: Vec<String> = wanted.iter().map(|path| permit_key(path)).collect();
        self.filters
            .iter()
            .filter(|(key, _)| !keys.contains(key))
            .map(|(key, ids)| (key.clone(), ids.clone()))
            .collect()
    }

    /// The applications of the list that are not permitted yet.
    fn fresh(&self, wanted: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for path in wanted {
            let key = permit_key(path);
            if key.is_empty() || self.filters.contains_key(&key) {
                continue;
            }
            if !out.iter().any(|seen: &String| permit_key(seen) == key) {
                out.push(path.clone());
            }
        }
        out
    }

    /// Remember the filters of an application.
    fn record(&mut self, path: &str, ids: Vec<u64>) {
        self.filters.insert(permit_key(path), ids);
    }

    /// Forget the filters of an application.
    fn forget(&mut self, path: &str) {
        self.filters.remove(&permit_key(path));
    }

    /// Every permit that is in force.
    fn all(&self) -> Vec<(String, Vec<u64>)> {
        self.filters
            .iter()
            .map(|(key, ids)| (key.clone(), ids.clone()))
            .collect()
    }
}

/// What has to happen to the permits when the list of the applications
/// changes.
#[derive(Debug, Default)]
struct PermitPlan {
    /// The filters of the applications that are not on the list any more.
    stale: Vec<(String, Vec<u64>)>,
    /// The applications of the list that are not permitted yet.
    fresh: Vec<String>,
}

/// The plan of the permits for a new list of applications.
fn plan_permits(permits: &AppPermits, wanted: &[String]) -> PermitPlan {
    PermitPlan {
        stale: permits.stale(wanted),
        fresh: permits.fresh(wanted),
    }
}

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
    /// Per-process filter tracking: normalized exe path → list of installed WFP filter IDs.
    /// On plane change the old IDs are deleted and a new set installed.
    per_process_filters: HashMap<String, Vec<u64>>,
    /// The filters that permit the applications which leave the tunnel.
    ///
    /// The driver binds them to the physical interface; the switch does not
    /// know about the driver and blocks everything it does not permit.  So
    /// the applications that are to work around the tunnel are permitted here
    /// by their own name -- otherwise the very switch that keeps the tunnel
    /// honest stops the work of the machine.
    ///
    /// The filters of the switch live in a persistent session: they survive
    /// the engine and the process.  So a permit that is not taken away
    /// stays for ever, and an application that was let out of the tunnel
    /// once would keep working around it for ever.  The bookkeeping knows
    /// WHICH application every filter belongs to, so the permits of the
    /// applications that are not on the list any more can go away.
    app_permits: AppPermits,
    /// The resolvers of the machine: they are permitted by address AND by the
    /// port of the name service.
    ///
    /// The router is the resolver on most lines, and the router is also the
    /// way out of the machine: every packet to the internet is addressed to
    /// it.  A permit for the whole local network therefore permits the whole
    /// internet as well -- the kill-switch would hold nothing.  So the
    /// resolver is permitted by its port, and the network around it is not
    /// permitted at all.
    resolvers: Vec<std::net::SocketAddr>,
    /// Should the UDP be locked as well?
    ///
    /// The lock over the connections is a layer of TCP.  UDP -- the games,
    /// the QUIC of the browsers, the questions of the machine -- would walk
    /// out of the machine untouched, and the person would get the internet
    /// without the tunnel they asked for.  So the UDP is locked too, while
    /// the tunnel does not carry yet: the door is left open for the
    /// questions of the machine and for the way out of the chain.
    lock_udp: bool,
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
            per_process_filters: HashMap::new(),
            app_permits: AppPermits::default(),
            resolvers: Vec::new(),
            lock_udp: false,
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

    /// The resolvers of the machine.
    ///
    /// They are permitted by their address AND by the port of the name
    /// service.  The router is the resolver on most lines, and the router is
    /// also the way out of the machine: every packet to the internet is
    /// addressed to it.  A permit for the whole local network would permit
    /// the whole internet with it, and the kill-switch would hold nothing.
    pub fn set_resolvers(&mut self, resolvers: Vec<std::net::SocketAddr>) {
        self.resolvers = resolvers;
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

    /// The kill-switch of the moment BEFORE the tunnel carries.
    ///
    /// The machine was told to tunnel: from now on nothing that is not the
    /// bypass may reach the internet. The traffic that is not in the tunnel
    /// yet would otherwise leave through the physical interface, and the
    /// person would get the internet without the tunnel they asked for.
    ///
    /// So: everything is blocked, and only what has to stay is let through --
    /// the loopback (the tunnel talks to itself over it), the local network
    /// (the router answers the questions of the machine, and the machines
    /// next door are not the internet), and the relays (the way out of the
    /// tunnel). The physical interface is NOT permitted as a whole: the holes
    /// of the bypass are routes, and they come a moment later.
    pub fn activate_pre_tunnel(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError> {
        self.native_if_index = None;
        // The local network is NOT permitted here.  The router answers the
        // questions of the machine AND carries its traffic to the internet:
        // a permit for the network around the router permits the internet
        // with it, and the person would get the internet without the tunnel
        // they asked for.  The resolver is permitted by its port instead.
        self.bypass_cidrs.clear();
        self.bypass_cidrs_v6.clear();
        // The UDP is locked as well while the tunnel does not carry.
        self.lock_udp = true;
        let result = self.activate(relay_addrs, tun_name, exempt_ports);
        self.lock_udp = false;
        result
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

        // 3b. Permit the resolvers by their address AND their port (weight 13).
        //
        // The router is the resolver on most lines, and the router is also
        // the way out of the machine: every packet to the internet is
        // addressed to it.  A permit for the whole local network would
        // permit the whole internet with it, and the kill-switch would hold
        // nothing -- the person would get the internet without the tunnel.
        for resolver in &self.resolvers {
            let IpAddr::V4(v4) = resolver.ip() else {
                continue;
            };
            FilterBuilder::new()
                .name("Mirage: permit resolver IPv4")
                .action(Action::Permit)
                .layer(Layer::ConnectV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(13))
                .condition(AddrConditionBuilder::remote().equal_v4(v4))
                .condition(PortConditionBuilder::remote().equal(resolver.port()))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("resolver permit {v4} failed: {e}")))?;
            info!(%v4, port = resolver.port(), "WFP: permit resolver IPv4");
        }

        // 3c. The lock over the UDP, while the tunnel does not carry.
        //
        // The block over the connections is a layer of TCP.  The UDP -- the
        // games, the QUIC of the browsers -- would walk out of the machine
        // untouched, and the person would get the internet without the
        // tunnel they asked for.  The door is left open for the questions
        // of the machine and for the way out of the chain.
        if self.lock_udp {
            FilterBuilder::new()
                .name("Mirage: block all outbound UDP IPv4")
                .action(Action::Block)
                .layer(Layer::OutboundTransportV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(1))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("block-all UDP IPv4 filter failed: {e}")))?;

            FilterBuilder::new()
                .name("Mirage: permit loopback UDP IPv4")
                .action(Action::Permit)
                .layer(Layer::OutboundTransportV4)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(15))
                .condition(AddrConditionBuilder::remote().subnet_v4(
                    u32::from(Ipv4Addr::new(127, 0, 0, 0)),
                    0xFF00_0000u32,
                ))
                .add(tx)
                .map_err(|e| TunError::Wfp(format!("loopback UDP permit failed: {e}")))?;

            for relay_addr in relay_addrs {
                if let IpAddr::V4(v4) = relay_addr {
                    FilterBuilder::new()
                        .name("Mirage: permit relay UDP IPv4")
                        .action(Action::Permit)
                        .layer(Layer::OutboundTransportV4)
                        .sublayer(KILLSWITCH_SUBLAYER_GUID)
                        .weight(Self::weight(14))
                        .condition(AddrConditionBuilder::remote().equal_v4(*v4))
                        .add(tx)
                        .map_err(|e| {
                            TunError::Wfp(format!("relay UDP permit {v4} failed: {e}"))
                        })?;
                }
            }

            for resolver in &self.resolvers {
                let IpAddr::V4(v4) = resolver.ip() else {
                    continue;
                };
                FilterBuilder::new()
                    .name("Mirage: permit resolver UDP IPv4")
                    .action(Action::Permit)
                    .layer(Layer::OutboundTransportV4)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(13))
                    .condition(AddrConditionBuilder::remote().equal_v4(v4))
                    .condition(PortConditionBuilder::remote().equal(resolver.port()))
                    .add(tx)
                    .map_err(|e| {
                        TunError::Wfp(format!("resolver UDP permit {v4} failed: {e}"))
                    })?;
            }
            info!("WFP: the UDP is locked until the tunnel carries");
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

        // 4b. Permit the physical interface for the traffic of the bypass.
        //
        // The traffic that leaves through it is the traffic of the holes of
        // the bypass (the addresses are permitted one by one as well) and the
        // traffic of the applications that leave the tunnel.  The permit is
        // one filter and not one per address: the list of the bypass holds
        // thousands of networks, and a filter for each of them costs the
        // device half a minute of its starting -- and a device that is slow
        // to start is a device that is killed before it carries.
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

        // 4b. The physical interface for the traffic of the bypass (weight 13).
        // The IPv4 side above says why it is one filter and not one per
        // address.
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

    /// Permit the applications that leave the tunnel.
    ///
    /// The driver binds them to the physical interface, and the switch does
    /// not know about the driver: it blocks everything that is not permitted.
    /// So the applications that are to work around the tunnel are permitted
    /// here by their own name -- they keep working even while the tunnel is
    /// stuck, and even while the driver is busy.
    ///
    /// The list REPLACES the old one: the permits of the applications that
    /// are not on it any more are taken away.  The filters of the switch
    /// survive the run, so a permit that is left behind would keep the
    /// application out of the tunnel for ever.
    pub fn install_app_permits(&mut self, app_paths: &[String]) -> Result<(), TunError> {
        let plan = plan_permits(&self.app_permits, app_paths);

        // The applications that are not on the list any more go back into
        // the tunnel: their permits go away.
        if !plan.stale.is_empty() {
            self.remove_app_permits(&plan.stale)?;
            for (path, _) in &plan.stale {
                info!(
                    app = %path,
                    "WFP: the application is not permitted past the switch any more"
                );
            }
        }

        if plan.fresh.is_empty() {
            return Ok(());
        }

        let engine = self
            .engine
            .as_mut()
            .ok_or_else(|| TunError::Other("the switch is not in force yet".into()))?;
        let tx = WfpTransaction::begin(engine)
            .map_err(|e| TunError::Wfp(format!("tx begin (app permit): {e}")))?;
        let mut installed: Vec<(String, Vec<u64>)> = Vec::new();
        for path in &plan.fresh {
            let cond = AppIdConditionBuilder::equal(path)
                .map_err(|e| TunError::Wfp(format!("app-id condition for {path}: {e}")))?;
            let mut ids = Vec::new();
            for layer in [Layer::ConnectV4, Layer::ConnectV6] {
                let id = FilterBuilder::new()
                    .name("Mirage: permit the application past the switch")
                    .action(Action::Permit)
                    .layer(layer)
                    .sublayer(KILLSWITCH_SUBLAYER_GUID)
                    .weight(Self::weight(15))
                    .condition(cond.clone())
                    .add(&tx)
                    .map_err(|e| TunError::Wfp(format!("app permit {path} {layer:?}: {e}")))?;
                ids.push(id);
            }
            info!(app = %path, "WFP: the application is permitted past the switch");
            installed.push((path.clone(), ids));
        }
        tx.commit().map_err(|e| TunError::Wfp(format!("tx commit (app permit): {e}")))?;
        for (path, ids) in installed {
            self.app_permits.record(&path, ids);
        }
        Ok(())
    }

    /// Take the filters of the given applications away.
    fn remove_app_permits(&mut self, stale: &[(String, Vec<u64>)]) -> Result<(), TunError> {
        if stale.is_empty() {
            return Ok(());
        }
        if let Some(engine) = self.engine.as_mut() {
            let tx = WfpTransaction::begin(engine)
                .map_err(|e| TunError::Wfp(format!("tx begin (app permit removal): {e}")))?;
            for (_, ids) in stale {
                for id in ids {
                    // Best-effort: the filter may be gone already.
                    let _ = delete_filter(&tx, *id);
                }
            }
            tx.commit()
                .map_err(|e| TunError::Wfp(format!("tx commit (app permit removal): {e}")))?;
        }
        for (path, _) in stale {
            self.app_permits.forget(path);
        }
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
        // Remove the permits of the applications that leave the tunnel.
        //
        // The filters of the switch survive the session, so they have to be
        // taken away here: an application that was let out of the tunnel
        // once would keep working around it for ever.
        let permits = self.app_permits.all();
        if let Err(e) = self.remove_app_permits(&permits) {
            warn!("WFP: the permits of the applications were not removed: {e}");
        }
        // Remove per-process filters (T3 addition) before closing the engine.
        if let Some(engine) = self.engine.as_mut() {
            if !self.per_process_filters.is_empty() {
                if let Ok(tx) = WfpTransaction::begin(engine) {
                    for ids in self.per_process_filters.values() {
                        for &id in ids {
                            let _ = delete_filter(&tx, id);
                        }
                    }
                    let _ = tx.commit();
                }
                self.per_process_filters.clear();
            }
        }
        // Existing coarse-filter cleanup.
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

// ── T3: PlatformExecutor impl ─────────────────────────────────────────────────

impl private::Sealed for WfpKillSwitch {}

impl WfpKillSwitch {
    /// Install per-process Bypass permit filters (ConnectV4 + ConnectV6, weight 11).
    /// Returns the list of installed filter IDs.
    fn install_bypass_filters(&mut self, app_id_bytes: &[u8]) -> Result<Vec<u64>, TunError> {
        let engine = self.engine.as_mut()
            .ok_or_else(|| TunError::Other("enforce called before activate".into()))?;
        let tx = WfpTransaction::begin(engine)
            .map_err(|e| TunError::Wfp(format!("tx begin (bypass): {e}")))?;

        let app_id_blob = OwnedByteBlob::from(app_id_bytes);
        let cond = AppIdConditionBuilder::equal_from_blob(app_id_blob)
            .map_err(|e| TunError::Wfp(format!("app-id condition: {e}")))?;

        let mut ids = Vec::with_capacity(2);

        for layer in [Layer::ConnectV4, Layer::ConnectV6] {
            let id = FilterBuilder::new()
                .name("Mirage: per-process bypass permit")
                .action(Action::Permit)
                .layer(layer)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(11))
                .condition(cond.clone())
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("bypass permit {layer:?}: {e}")))?;
            ids.push(id);
        }

        tx.commit().map_err(|e| TunError::Wfp(format!("tx commit (bypass): {e}")))?;
        Ok(ids)
    }

    /// Install per-process Kill/Wire block filters:
    ///   - ConnectV4 + ConnectV6 block (weight 8) — blocks all TCP/UDP/ICMP egress.
    ///   - AleResourceAssignmentV4 + V6 block with IS_RAW_ENDPOINT (weight 8) —
    ///     blocks raw socket creation.
    ///
    /// // TODO(T3-follow): also block promiscuous mode via FWPM_CONDITION_ALE_PROMISCUOUS_MODE
    ///
    /// Returns the list of installed filter IDs.
    fn install_kill_filters(&mut self, app_id_bytes: &[u8]) -> Result<Vec<u64>, TunError> {
        let engine = self.engine.as_mut()
            .ok_or_else(|| TunError::Other("enforce called before activate".into()))?;
        let tx = WfpTransaction::begin(engine)
            .map_err(|e| TunError::Wfp(format!("tx begin (kill): {e}")))?;

        let app_id_blob = OwnedByteBlob::from(app_id_bytes);
        let app_id_cond = AppIdConditionBuilder::equal_from_blob(app_id_blob)
            .map_err(|e| TunError::Wfp(format!("app-id condition: {e}")))?;
        let raw_ep_cond = FlagsConditionBuilder::any_set(FLAG_IS_RAW_ENDPOINT);

        let mut ids = Vec::with_capacity(4);

        // Block connect-path egress (TCP/UDP/ICMP).
        for layer in [Layer::ConnectV4, Layer::ConnectV6] {
            let id = FilterBuilder::new()
                .name("Mirage: per-process egress block")
                .action(Action::Block)
                .layer(layer)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(8))
                .condition(app_id_cond.clone())
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("egress block {layer:?}: {e}")))?;
            ids.push(id);
        }

        // Block raw socket creation (IS_RAW_ENDPOINT at ALE_RESOURCE_ASSIGNMENT).
        for layer in [Layer::AleResourceAssignmentV4, Layer::AleResourceAssignmentV6] {
            let id = FilterBuilder::new()
                .name("Mirage: per-process raw socket block")
                .action(Action::Block)
                .layer(layer)
                .sublayer(KILLSWITCH_SUBLAYER_GUID)
                .weight(Self::weight(8))
                .condition(app_id_cond.clone())
                .condition(raw_ep_cond.clone())
                .add(&tx)
                .map_err(|e| TunError::Wfp(format!("raw socket block {layer:?}: {e}")))?;
            ids.push(id);
        }

        tx.commit().map_err(|e| TunError::Wfp(format!("tx commit (kill): {e}")))?;
        Ok(ids)
    }

    /// Remove per-process filters previously installed for `exe_key`.
    /// Best-effort: individual filter-delete errors are ignored (process may have died).
    fn remove_per_process_filters(&mut self, exe_key: &str) -> Result<(), TunError> {
        if let Some(ids) = self.per_process_filters.remove(exe_key) {
            if let Some(engine) = self.engine.as_mut() {
                let tx = WfpTransaction::begin(engine)
                    .map_err(|e| TunError::Wfp(format!("tx begin (remove): {e}")))?;
                for id in ids {
                    // Best-effort: if filter already gone (process died), ignore.
                    let _ = delete_filter(&tx, id);
                }
                tx.commit().map_err(|e| TunError::Wfp(format!("tx commit (remove): {e}")))?;
            }
        }
        Ok(())
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
    /// Acquires the WFP app-id blob via `FwpmGetAppIdFromFileName0` using the raw
    /// Win32 path (pre-normalization) and stores it as `platform_token`. If blob
    /// acquisition fails (e.g. process exited), `platform_token` is `None`.
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
        // Use raw_exe_path (pre-normalization Win32 form) for FwpmGetAppIdFromFileName0.
        // The normalized exe_path (forward slashes) is rejected by WFP.
        let token: Option<Vec<u8>> = mirage_wfp::app_id_from_filename(
            OsStr::new(&local_info.raw_exe_path)
        )
        .ok()
        .map(|blob| {
            // SAFETY: blob pointer is valid; we copy the bytes out immediately via as_ptr.
            let ptr = blob.as_ptr();
            let size = unsafe { (*ptr).size as usize };
            let data = unsafe { std::slice::from_raw_parts((*ptr).data, size) };
            data.to_vec()
        });
        let core_info = crate::process_info::process_info_to_core(local_info);
        Some(ProcessIdentity::with_token(core_info, token.unwrap_or_default()))
    }

    /// Enforce the plane decision by installing or replacing per-process WFP filters.
    ///
    /// - `Plane::Group` must never reach this method; returns `Err` immediately.
    /// - Without a non-empty `platform_token` the per-process filters cannot be installed;
    ///   the coarse block-all (weight 1) remains in effect — safe default (fail-closed).
    /// - `Plane::Bypass` → install weight-11 APP_ID permit on ConnectV4/V6.
    /// - `Plane::Wire(_)` or `Plane::Kill` → install weight-8 APP_ID block on ConnectV4/V6
    ///   and weight-8 APP_ID+IS_RAW_ENDPOINT block on AleResourceAssignmentV4/V6.
    fn enforce(
        &mut self,
        plane: &Plane,
        identity: Option<&ProcessIdentity>,
        flow: &FlowKey,
    ) -> Result<(), TunError> {
        // Group must be resolved before reaching enforce.
        if matches!(plane, Plane::Group(_)) {
            tracing::error!(?flow, "enforce called with unresolved Group plane — bug in caller");
            return Err(TunError::Other("unresolved Group plane in enforce".into()));
        }

        // Without a non-empty attribution token we cannot install per-process filters.
        // The coarse block-all (weight 1) from activate() remains in effect — safe.
        let (exe_key, app_id_bytes) = match identity {
            Some(id) if !id.platform_token.as_deref().unwrap_or(&[]).is_empty() => {
                (id.info.exe_path.clone(), id.platform_token.clone().unwrap())
            }
            _ => {
                tracing::debug!(?flow, "no attribution token — skipping per-process filter");
                return Ok(());
            }
        };

        // Remove previous filter set for this exe (plane transition).
        self.remove_per_process_filters(&exe_key)?;

        // Install new filter set based on plane.
        let filter_ids = match plane {
            Plane::Bypass => self.install_bypass_filters(&app_id_bytes)?,
            Plane::Wire(_) | Plane::Kill => self.install_kill_filters(&app_id_bytes)?,
            Plane::Group(_) => unreachable!("Group checked above"),
        };

        self.per_process_filters.insert(exe_key, filter_ids);
        Ok(())
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_tun_core::plane::{Plane, ProcessIdentity};
    use mirage_tun_core::policy::ProcessInfo as CoreProcessInfo;
    use mirage_tun_core::traits::{FlowKey, FlowProto};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_flow_key() -> FlowKey {
        FlowKey {
            src_port: 12345,
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            proto: FlowProto::Tcp,
        }
    }

    fn make_identity_no_token() -> ProcessIdentity {
        ProcessIdentity::from_process_info(CoreProcessInfo {
            pid: 1234,
            exe_path: "c:/windows/notepad.exe".to_owned(),
            ancestor_paths: vec![],
        })
    }

    #[test]
    fn wfp_kill_switch_new_has_empty_per_process() {
        let ks = WfpKillSwitch::new();
        assert!(ks.per_process_filters.is_empty(), "new() must start with empty per_process_filters");
    }

    #[test]
    fn enforce_group_returns_error() {
        let mut ks = WfpKillSwitch::new();
        let flow = make_flow_key();
        let result = ks.enforce(&Plane::Group("g".to_owned()), None, &flow);
        assert!(result.is_err(), "enforce with Group plane must return Err");
        if let Err(TunError::Other(msg)) = result {
            assert!(msg.contains("Group"), "error message should mention Group");
        }
    }

    #[test]
    fn enforce_no_token_is_noop() {
        // With no engine and no token, enforce should return Ok(()) without panic.
        let mut ks = WfpKillSwitch::new();
        let flow = make_flow_key();
        let identity = make_identity_no_token();
        // Kill plane + no token → Ok(()) (no WFP call attempted since token is empty).
        let result = ks.enforce(&Plane::Kill, Some(&identity), &flow);
        assert!(result.is_ok(), "enforce with no token must be a no-op (Ok)");
        assert!(ks.per_process_filters.is_empty(), "no filter should be inserted when token is absent");
    }

    /// The filters of the switch survive the run: an application that was
    /// let out of the tunnel once would keep working around it for ever.
    /// So the permits of the applications that are not on the list any more
    /// have to be taken away.
    #[test]
    fn a_stale_application_is_not_permitted_any_more() {
        let mut permits = AppPermits::default();
        permits.record("C:\\Program Files\\nodejs\\node.exe", vec![10, 11]);

        // The list changes: the old application is not on it any more.
        let wanted = vec!["C:\\tools\\codex\\codex.exe".to_owned()];
        let plan = plan_permits(&permits, &wanted);
        assert_eq!(plan.stale.len(), 1, "the old permit is taken away");
        assert_eq!(
            plan.stale[0].1,
            vec![10, 11],
            "the filters of the old application are the ones that go away"
        );
        assert_eq!(plan.fresh, wanted, "the new application is permitted");

        // The plan is carried out.
        for (path, _) in &plan.stale {
            permits.forget(path);
        }
        for path in &plan.fresh {
            permits.record(path, vec![20, 21]);
        }

        // The old application is not permitted any more.
        let in_force = permits.all();
        assert_eq!(in_force.len(), 1);
        assert!(
            in_force[0].0.contains("codex.exe"),
            "only the new application is permitted: {:?}",
            in_force
        );
        assert!(
            permits.stale(&wanted).is_empty(),
            "nothing stale is left behind"
        );
    }

    #[test]
    fn the_same_list_twice_changes_nothing() {
        let mut permits = AppPermits::default();
        permits.record("C:\\a.exe", vec![1]);
        let wanted = vec!["C:\\a.exe".to_owned()];
        let plan = plan_permits(&permits, &wanted);
        assert!(plan.stale.is_empty(), "the application is still on the list");
        assert!(plan.fresh.is_empty(), "it is permitted already");
    }

    /// The same path in two spellings is the same application.
    #[test]
    fn the_same_path_in_two_spellings_is_one_application() {
        let mut permits = AppPermits::default();
        permits.record("C:/tools/a.exe", vec![1]);
        let wanted = vec!["c:\\tools\\a.exe".to_owned()];
        let plan = plan_permits(&permits, &wanted);
        assert!(plan.stale.is_empty(), "the application is still on the list");
        assert!(plan.fresh.is_empty(), "it is permitted already");
    }

    /// An empty list takes every permit away.
    #[test]
    fn an_empty_list_takes_every_permit_away() {
        let mut permits = AppPermits::default();
        permits.record("C:\\a.exe", vec![1]);
        let plan = plan_permits(&permits, &[]);
        assert_eq!(plan.stale.len(), 1);
        assert!(plan.fresh.is_empty());
    }
}
