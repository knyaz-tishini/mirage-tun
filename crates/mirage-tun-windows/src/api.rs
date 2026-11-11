use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use futures::StreamExt;
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

/// Emitted at most once across the process lifetime.
static UNAUTHED_WARNED: OnceLock<()> = OnceLock::new();

use mirage_tun_core::traits::PlatformFirewall;

use crate::chains::{ChainConfig, ChainEntry, ChainMap, ChainProtocol, ChainRegistry};
use crate::config::TunConfig;
use crate::error::TunError;
use crate::ipstack::IpStackRunner;
use crate::metrics::MetricsRegistry;
use crate::rawip::RawIpRunner;
use crate::routing::Routing;
use crate::state::{ServiceState, TunPhase};

/// DNS server used in raw-IP mode when the configured upstream is unusable.
const FALLBACK_DNS: &str = "1.1.1.1";

/// How long a name may take to answer when the holes are drilled.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// How many names are asked at the same time when the holes are drilled.
const RESOLVE_PARALLEL: usize = 16;

#[derive(Serialize, Deserialize)]
pub struct TunStartParams {
    /// Legacy single-proxy address. Used when `chains` is empty.
    #[serde(default)]
    pub socks5_addr: String,
    #[serde(default)]
    pub relay_addrs: Vec<String>,
    #[serde(default)]
    pub policy: Option<mirage_tun_core::policy::PolicyConfigRequest>,
    /// Named SOCKS5 chains. If empty and `socks5_addr` is set, synthesizes
    /// a single "default" chain from `socks5_addr` for backward compat.
    #[serde(default)]
    pub chains: Vec<ChainConfig>,
}

#[derive(Deserialize)]
pub struct ProxySetParams {
    pub proxy_server: String,
}

#[derive(Deserialize)]
pub struct ChainsUpdateParams {
    pub chains: Vec<ChainConfig>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub adapter_alive: bool,
    pub tun_phase: TunPhase,
    pub proxy_active: Option<String>,
    pub socks5_addr: Option<String>,
    pub policy_rules: usize,
    pub dns_map_size: usize,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub struct AppState {
    pub service: Arc<Mutex<ServiceState>>,
    pub stop_tx: watch::Sender<()>,
    pub policy: Arc<mirage_tun_core::policy::PolicyEngine>,
    pub dns_map: Arc<crate::dns_map::DnsMap>,
    pub chains: Arc<ChainRegistry>,
    pub metrics: Arc<MetricsRegistry>,
    pub connections: Arc<crate::metrics::ConnectionRegistry>,
    pub config: Arc<TunConfig>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    // Routes that are always open (unauthenticated health/metrics scrapers).
    let open = Router::new()
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics))
        .route("/connections", get(get_connections));

    // All mutating and state-exposing routes require auth when api_key is set.
    let guarded = Router::new()
        .route("/status", get(get_status))
        .route("/config", get(get_config))
        .route("/tun/start", post(post_tun_start))
        .route("/tun/stop", post(post_tun_stop))
        .route("/proxy/set", post(post_proxy_set))
        .route("/proxy/clear", post(post_proxy_clear))
        .route("/admin/restart", post(post_admin_restart))
        .route("/policy/get", get(get_policy))
        .route("/policy/set", post(set_policy))
        .route("/chains/list", get(get_chains_list))
        .route("/chains/update", post(post_chains_update));

    // Wrap guarded routes with the Bearer middleware when api_key is configured.
    let guarded = match state.config.api_key.clone() {
        Some(key) => {
            let key = Arc::new(key);
            guarded.layer(middleware::from_fn_with_state(key, bearer_gate))
        }
        None => {
            UNAUTHED_WARNED.get_or_init(|| {
                warn!(
                    "TUN control API is unauthenticated — set `api_key` in tun.json to enable Bearer enforcement"
                );
            });
            guarded
        }
    };

    open.merge(guarded).with_state(state)
}

/// Axum middleware: require `Authorization: Bearer <key>`.
/// Constant-time compare guards against timing attacks.
async fn bearer_gate(
    State(key): State<Arc<String>>,
    req: Request,
    next: Next,
) -> Response {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    // Constant-time compare: equal length AND byte-by-byte fold.
    let ok = provided.map_or(false, |tok| {
        let a = tok.as_bytes();
        let b = key.as_bytes();
        a.len() == b.len()
            && a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    });

    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    }
}

async fn get_health() -> StatusCode {
    StatusCode::OK
}

async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::to_value(state.config.as_ref()).unwrap_or(serde_json::Value::Null))
}

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Json<StatusResponse> {
    let s = state.service.lock().await;
    let policy_rules = state.policy.get_config().await.rules.len();
    let dns_map_size = state.dns_map.len();
    Json(StatusResponse {
        adapter_alive: s.wintun.is_some(),
        tun_phase: s.tun_phase.clone(),
        proxy_active: s.proxy_active.clone(),
        socks5_addr: s.socks5_addr.map(|a| a.to_string()),
        policy_rules,
        dns_map_size,
    })
}

pub async fn activate_tun_inner(
    state: &Arc<AppState>,
    params: TunStartParams,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<(), TunError> {
    // Resolve TUN interface index via spawn_blocking BEFORE taking the mutex so
    // we don't block the async executor with a sync subprocess call while holding
    // a lock.
    let tun_name_pre = {
        let s = state.service.lock().await;
        if s.wintun.is_none() {
            return Err(TunError::AdapterNotReady);
        }
        if s.tun_phase == TunPhase::TunActive {
            return Err(TunError::AlreadyActive);
        }
        s.tun_name.clone()
    };
    let tun_name_for_resolve = tun_name_pre.clone();
    let pre_resolved_tun_idx = tokio::task::spawn_blocking(move || {
        crate::firewall::resolve_interface_index(&tun_name_for_resolve)
    })
    .await
    .unwrap_or(None);

    let mut s = state.service.lock().await;

    // Re-check state after the brief unlock above.
    if s.wintun.is_none() {
        return Err(TunError::AdapterNotReady);
    }
    if s.tun_phase == TunPhase::TunActive {
        return Err(TunError::AlreadyActive);
    }

    // Build chain configs — backward compat: if `chains` is empty but `socks5_addr`
    // is present, synthesize a single "default" chain.
    let chain_configs: Vec<ChainConfig> = if params.chains.is_empty() && !params.socks5_addr.is_empty() {
        vec![ChainConfig { name: "default".to_owned(), socks5_addr: params.socks5_addr.clone(), protocol: ChainProtocol::Socks5, dns_upstream: None }]
    } else {
        params.chains.clone()
    };

    if chain_configs.is_empty() {
        return Err(TunError::Other("no chains configured and no socks5_addr provided".to_owned()));
    }

    // Resolve the "default" chain address (used for DNS warmup / legacy path).
    let default_socks5: SocketAddr = chain_configs
        .iter()
        .find(|c| c.name == "default")
        .or_else(|| chain_configs.first())
        .ok_or_else(|| TunError::Other("no chain available".to_owned()))
        .and_then(|c| {
            c.socks5_addr.parse::<SocketAddr>()
                .map_err(|e| TunError::Other(format!("invalid socks5_addr '{}': {e}", c.socks5_addr)))
        })?;

    s.tun_phase = TunPhase::Transitioning;

    let tun_name = s.tun_name.clone();

    // The device was asked to stop while it was starting: the routes must
    // not go up behind the back of the shutdown.  A device that is killed
    // mid-start leaves its routes behind, and the machine loses its way out.
    if cancel.is_cancelled() {
        s.tun_phase = TunPhase::AdapterReady;
        return Err(TunError::Other("the device was asked to stop while starting".to_owned()));
    }

    let t0 = std::time::Instant::now();

    let raw_ip_mode = state.config.is_raw_ip();

    // The kill-switch goes up FIRST.
    //
    // From the moment the machine is told to tunnel, nothing that is not the
    // bypass may reach the internet: the traffic that is not in the tunnel
    // yet would otherwise go out through the physical interface and the
    // person would get the internet without the tunnel they asked for. The
    // holes of the bypass are drilled a moment later; until then the machine
    // is closed, which is the truth of the moment.
    let (early_gateway, early_if_index) =
        crate::routing::read_default_gateway_v4().await.unwrap_or_default();
    let mut early_relay_ips: Vec<IpAddr> = Vec::new();
    for relay in &params.relay_addrs {
        if let Ok(ip) = relay.parse::<IpAddr>() {
            early_relay_ips.push(ip);
        }
    }
    let mut early_killswitch = crate::firewall::WfpKillSwitch::new();
    early_killswitch.set_native_if_index(early_if_index);
    if let Err(e) = early_killswitch.activate_pre_tunnel(&early_relay_ips, &tun_name, &[]) {
        warn!("WFP kill-switch failed to activate before the tunnel (non-fatal): {e}");
    } else {
        info!("activate: the kill-switch is up before the tunnel");
    }

    // The adapter's IPv6 address: the tunnel carries whole IP packets, so
    // the host's IPv6 has to ride it as well.  The address is the one the
    // config names, or the one derived from the IPv4 address
    // (10.77.0.N -> fd77::N/64).
    //
    // Only the raw-IP mode forwards packets at L3: in the stack mode the
    // userspace TCP/IP stack terminates IPv4 alone, and IPv6 handed to it
    // would be dropped on the way.
    let ipv6_addr = tunnel_ipv6_addr(state.config.as_ref());
    let mut ipv6_enabled = false;
    if let Some(addr) = ipv6_addr.as_deref() {
        let name = tun_name.clone();
        let addr_cidr = addr.to_owned();
        let assigned = tokio::task::spawn_blocking(move || {
            crate::wintun::assign_ipv6_address(&name, &addr_cidr)
        })
        .await
        .unwrap_or_else(|e| {
            Err(TunError::Wintun(format!("spawn_blocking panicked: {e}")))
        });
        match assigned {
            Ok(()) => {
                ipv6_enabled = true;
                info!(addr = %addr, "activate: IPv6 address assigned");
            }
            Err(e) => warn!("activate: IPv6 address {addr} was not assigned: {e}"),
        }
    }

    // Routes AFTER adapter exists — otherwise they vanish with destroyed interface
    let mut routing = Routing::new(&tun_name);
    // The IPv6 half-routes go in only when the adapter has an IPv6 address:
    // a route into an adapter without one would black-hole the host's IPv6.
    routing.set_ipv6_enabled(ipv6_enabled);
    routing.set_default_route().await?;
    info!("activate: set_default_route = {}ms", t0.elapsed().as_millis());

    let if_index = routing.original_interface_idx().unwrap_or(0);
    let gateway = routing.original_gateway().map(str::to_owned);

    // D5: use pinned direct_dns from config when set; skip OS discovery entirely.
    let native_dns = if let Some(pinned) = state.config.direct_dns {
        info!("native_dns: using pinned direct_dns={pinned}");
        Some(pinned)
    } else {
        let dns = discover_native_dns(if_index).await;
        info!("native_dns discovered: {dns:?}");
        dns
    };
    // The names of the bypass are asked of every resolver of the machine:
    // the one the interface names and the router, which answers when the
    // provider filters the questions to the others.
    let native_resolvers = native_resolvers(if_index, gateway.as_deref(), native_dns).await;

    let mut relay_ips: Vec<IpAddr> = Vec::new();
    for relay in &params.relay_addrs {
        if let Ok(ip) = relay.parse::<IpAddr>() {
            routing.add_bypass(ip).await?;
            relay_ips.push(ip);
        }
    }
    info!("activate: bypass routes = {}ms", t0.elapsed().as_millis());

    // Compile policy from params early so we can extract bypass CIDRs for WFP.
    let initial_policy = params.policy.map(|policy_req| {
        mirage_tun_core::policy::CompiledPolicy::compile(policy_req.rules, policy_req.default_action)
    });

    // The bypass the person asked for: the destinations that must leave the
    // machine the way they always did.
    //
    // The adapter takes EVERY packet when the tunnel is up, so the only way
    // out for an excluded destination is a HOLE in the routing: the prefix
    // gets a route through the gateway the machine had before the tunnel, and
    // those packets never reach the adapter at all.
    //
    // A network is a hole right away. A NAME is a hole that follows the
    // name: the addresses of a CDN change under it, so the name is resolved
    // again while the tunnel is up and the holes follow.
    let mut plan = crate::bypass::BypassPlan::from_policy(initial_policy.as_ref());
    plan.merge(crate::bypass::BypassPlan::from_config(&state.config.bypass));
    // The networks of the preset are not drilled: a hole is a route in the
    // routing table, and the list of a country is thousands of prefixes.
    // They stay in the policy, and the data plane walks out with them.
    if let Some(preset) = crate::preset::Preset::get() {
        let preset_cidrs = preset.cidr_strings();
        plan.cidrs.retain(|cidr| !preset_cidrs.contains(&cidr.trim().to_ascii_lowercase()));
        // The NAMES of the preset ARE drilled.  The adapter takes every
        // packet when the tunnel is up, so a name can only leave the
        // machine through a hole that follows its addresses -- the watcher
        // drills those holes.  Without this the names of the preset would
        // go into the tunnel like everything else.
        plan.merge(crate::bypass::BypassPlan {
            cidrs: Vec::new(),
            domains: preset.domain_strings(),
            apps: Vec::new(),
        });
    }
    crate::bypass::log_plan(&plan);

    // The networks: a hole each.
    //
    // The NAMES are not drilled here: a name is a question to a resolver,
    // and the answer must not hold the tunnel hostage while it comes.  The
    // watcher drills those holes right after the device is up.
    let tunnel_addr = state
        .config
        .tun_addr
        .split('/')
        .next()
        .and_then(|addr| addr.trim().parse::<IpAddr>().ok());
    for cidr in &plan.cidrs {
        if !crate::bypass::hole_is_safe(cidr, tunnel_addr) {
            warn!(cidr, "activate: the hole would break the machine itself; it was NOT drilled");
            continue;
        }
        if let Err(e) = routing.add_bypass_cidr(cidr).await {
            warn!(cidr, "activate: the bypass hole was refused: {e}");
        }
    }
    if !plan.cidrs.is_empty() {
        info!(networks = plan.cidrs.len(), "activate: the bypass holes are in place");
    }

    // The resolver the adapter asks.
    //
    // With no excluded names, the names go through the tunnel: the adapter
    // asks the upstream of the tunnel.  With excluded names the watcher
    // takes the adapter over -- it points the adapter at the machine's own
    // resolver as soon as that resolver has answered a question.
    if plan.domains.is_empty() {
        let dns_ip = if raw_ip_mode && !is_usable_dns(state.config.dns_upstream) {
            warn!(
                "raw_ip mode: dns_upstream {} is not usable - using {FALLBACK_DNS}",
                state.config.dns_upstream
            );
            FALLBACK_DNS.to_owned()
        } else {
            state.config.dns_upstream.ip().to_string()
        };
        let _ = tokio::process::Command::new("netsh")
            .args(["interface", "ip", "set", "dns", &tun_name, "static", &dns_ip])
            .output()
            .await;
    }

    // WFP: the holes must be permitted, or the kill-switch would cut the
    // very traffic they exist for.
    let mut bypass_cidrs_for_wfp: Vec<(u32, u32)> = Vec::new();
    let mut bypass_cidrs_v6_for_wfp: Vec<(u128, u128)> = Vec::new();
    for cidr in &plan.cidrs {
        if let Some(v) = crate::bypass::cidr_to_wfp(cidr) {
            bypass_cidrs_for_wfp.push(v);
        }
        if let Some(v) = crate::bypass::cidr_to_wfp_v6(cidr) {
            bypass_cidrs_v6_for_wfp.push(v);
        }
    }
    for hole in routing.bypass_holes() {
        if let Some(v) = crate::bypass::cidr_to_wfp(&hole.cidr) {
            bypass_cidrs_for_wfp.push(v);
        }
        if let Some(v) = crate::bypass::cidr_to_wfp_v6(&hole.cidr) {
            bypass_cidrs_v6_for_wfp.push(v);
        }
    }

    // Activate WFP kill-switch (needs if_index for native bypass permit).
    // TUN interface index was resolved via spawn_blocking before taking the mutex.
    if cancel.is_cancelled() {
        // The routes are up and nobody wants them: the routing gives them
        // back on the way out.
        return Err(TunError::Other("the device was asked to stop while starting".to_owned()));
    }
    let mut killswitch = crate::firewall::WfpKillSwitch::new();
    killswitch.set_native_if_index(if_index);
    if let Some(tun_idx) = pre_resolved_tun_idx {
        killswitch.set_tun_if_index(tun_idx);
    }
    killswitch.set_bypass_cidrs(bypass_cidrs_for_wfp);
    killswitch.set_bypass_cidrs_v6(bypass_cidrs_v6_for_wfp);
    if let Err(e) = killswitch.activate(&relay_ips, &tun_name, &[]) {
        warn!("WFP kill-switch failed to activate (non-fatal): {e}");
    }

    // The applications that leave the tunnel.
    //
    // The bypass above is about destinations; this is about the images: the
    // listed applications keep using the physical interface while everything
    // else goes through the tunnel.  The work is done by the split-tunnel
    // driver — if it is not there, the tunnel goes on without it.
    //
    // The list comes from two places: the explicit `split_tunnel_apps`, and
    // the application rules of the policy (an application the policy sends
    // around the tunnel should leave it BY APPLICATION as well).  Whoever
    // writes tun.json may fill in one and not the other.
    let mut applications = state.config.split_tunnel_apps.clone();
    if let Some(preset) = crate::preset::Preset::get() {
        for app in &preset.apps {
            let app = app.trim();
            if !app.is_empty() && !applications.iter().any(|a| a.eq_ignore_ascii_case(app)) {
                applications.push(app.to_owned());
            }
        }
    }
    if let Some(policy) = state.config.policy.as_ref() {
        for rule in &policy.rules {
            if let mirage_tun_core::policy::PolicyRule::DestAppPath { path, action, .. } = rule {
                if matches!(action, mirage_tun_core::policy::PolicyDecision::Bypass)
                    && !applications.iter().any(|a| a.eq_ignore_ascii_case(path))
                {
                    applications.push(path.clone());
                }
            }
        }
    }
    if !applications.is_empty() {
        let tunnel_ip = state
            .config
            .tun_addr
            .split('/')
            .next()
            .and_then(|a| a.trim().parse::<std::net::Ipv4Addr>().ok());
        let internet_ip = gateway
            .as_ref()
            .and_then(|g| g.parse::<std::net::IpAddr>().ok())
            .and_then(crate::split_tunnel::local_address_for);
        match (tunnel_ip, internet_ip) {
            (Some(tunnel), Some(internet)) => {
                let engaged = tokio::task::spawn_blocking(move || {
                    crate::split_tunnel::SplitTunnel::engage(tunnel, internet, &applications)
                })
                .await;
                match engaged {
                    Ok(Ok(split)) => {
                        info!("activate: the split-tunnel is engaged");
                        s.split_tunnel = Some(split);
                    }
                    Ok(Err(e)) => warn!("activate: the split-tunnel did not engage (non-fatal): {e}"),
                    Err(e) => warn!("activate: the split-tunnel panicked (non-fatal): {e}"),
                }
            }
            _ => warn!(
                "activate: the split-tunnel needs the tunnel address and the physical address; it was not engaged"
            ),
        }
    }

    let cancel = tokio_util::sync::CancellationToken::new();

    let process_resolver = Arc::new(crate::process_info::ProcessResolver::new());

    // Populate the shared chain registry BEFORE starting the ipstack so that
    // IpStackRunner holds a live Arc<ChainRegistry> and always sees current chains.
    let new_map: ChainMap = chain_configs.iter().filter_map(|c| {
        let socks5_addr = c.socks5_addr.parse::<SocketAddr>().ok()?;
        let dns_upstream = c.dns_upstream.as_ref().and_then(|d| d.parse::<SocketAddr>().ok());
        Some((c.name.clone(), ChainEntry { chain_id: c.name.clone(), socks5_addr, dns_upstream }))
    }).collect();
    let protocols: HashMap<String, ChainProtocol> = chain_configs
        .iter()
        .map(|c| (c.name.clone(), c.protocol.clone()))
        .collect();
    state.chains.update_with_protocols(new_map, protocols).await;

    let bypass_addrs_store = relay_ips.clone();
    let wintun = s.wintun.as_ref().ok_or(TunError::AdapterNotReady)?;
    let device = crate::wintun::WintunDevice::new(wintun);
    if raw_ip_mode {
        // Raw-IP mode: whole IP packets go to the client and come back the
        // same way.  Nothing is terminated on this side.
        let runner = RawIpRunner::start(
            device,
            Arc::clone(&state.chains),
            cancel.clone(),
            if_index,
            &state.config,
        )
        .await?;
        s.active_conns = Some(runner.active_conns);
    } else {
        let runner = IpStackRunner::start(
            device,
            Arc::clone(&state.chains),
            cancel.clone(),
            relay_ips,
            if_index,
            Arc::clone(&state.policy),
            Arc::clone(&state.dns_map),
            native_dns,
            process_resolver,
            Arc::clone(&state.metrics),
            Arc::clone(&state.connections),
            &state.config,
        )
        .await?;
        s.active_conns = Some(runner.active_conns);
    }
    s.drain_timeout_secs = state.config.drain_timeout_secs;
    s.dns_upstream = state.config.dns_upstream;
    s.ipstack_cancel = Some(cancel.clone());
    s.socks5_addr = Some(default_socks5);
    s.killswitch = Some(killswitch);
    s.tun_phase = TunPhase::TunActive;
    s.if_index = if_index;
    s.chains = Arc::clone(&state.chains);

    // Store routing state
    s.original_gateway = routing.original_gateway().map(|s| s.to_owned());
    s.tun_default_set = true;
    s.bypass_addrs = bypass_addrs_store;
    s.bypass_holes = routing.bypass_holes();
    // Prevent Drop from restoring routes — we'll do it manually on stop
    std::mem::forget(routing);

    // The networks of the preset leave the tunnel as well.  The exclusions
    // of the machine are routes to the gateway it had before the tunnel, and
    // they go in through the routing API of the system -- one route per
    // network, in one go, the way the other clients do it.  A separate
    // process per network would take hours for a list of a country.
    if let Some(preset) = crate::preset::Preset::get() {
        let networks: Vec<String> = preset
            .cidr_strings()
            .into_iter()
            .filter(|cidr| !cidr.contains(':'))
            .filter(|cidr| crate::bypass::hole_is_safe(cidr, tunnel_addr))
            .collect();
        if !networks.is_empty() {
            let state = Arc::clone(state);
            let gateway = gateway.clone();
            tokio::spawn(async move {
                let holes =
                    crate::routing::drill_holes_batch(&networks, gateway.as_deref(), if_index).await;
                info!(
                    networks = holes.len(),
                    "bypass: the networks of the preset leave the tunnel"
                );
                for hole in holes {
                    remember_hole(&state, hole).await;
                }
            });
        }
    }

    // The names are holes that follow the name: the addresses of a CDN
    // change under it, so the holes are drilled again and again while the
    // tunnel is up.
    if !plan.domains.is_empty() {
        spawn_bypass_watcher(
            Arc::clone(state),
            plan.domains.clone(),
            native_resolvers.clone(),
            state.config.dns_upstream,
            gateway,
            if_index,
            tunnel_addr,
            BTreeSet::new(),
            cancel.clone(),
        );
    }

    if let Some(compiled) = initial_policy {
        state.policy.update(compiled).await;
        info!("Policy loaded from TUN start params");
    }

    info!("TUN started, default_socks5={default_socks5}, chains={}", chain_configs.len());
    Ok(())
}

/// The prefix length of a host route.
fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// True when the address needs a hole of its own.
///
/// A private address already leaves the machine: the network of the router
/// has a route of its own, and that route is more specific than the
/// tunnel's default.  A public address has no such route -- it would go
/// into the tunnel without a hole.
fn needs_hole(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // carrier-grade NAT: 100.64.0.0/10
                || (octets[0] == 100 && (64..128).contains(&octets[1])))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local: fc00::/7
                || (segments[0] & 0xfe00) == 0xfc00)
        }
    }
}

/// The holes follow the names.
///
/// The addresses of a CDN change under it while the tunnel is up, so the
/// names are resolved again and again: every address a name points at gets
/// a hole of its own, and the traffic of that name leaves the machine the
/// way it always did.
fn spawn_bypass_watcher(
    state: Arc<AppState>,
    domains: Vec<String>,
    native_resolvers: Vec<SocketAddr>,
    tunnel_dns: SocketAddr,
    gateway: Option<String>,
    if_index: u32,
    tunnel_addr: Option<IpAddr>,
    known: BTreeSet<IpAddr>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let interval = Duration::from_secs(state.config.bypass_refresh_secs.max(5));
    tokio::spawn(async move {
        let mut known = known;
        let mut resolver_holed = false;
        let mut dns_answered = false;
        // The resolver that answers: it becomes the adapter's own.
        let mut answered_resolver: Option<SocketAddr> = None;
        // The resolvers that are asked.  A resolver that stays silent is
        // dropped after the first round: on a line where the provider filters
        // the questions to some of them, waiting for the silent one costs
        // every name three seconds.
        let mut live_resolvers = native_resolvers.clone();
        info!(
            names = domains.len(),
            resolvers = native_resolvers.len(),
            every = interval.as_secs(),
            "bypass: the watcher is watching the names"
        );
        loop {
            // The resolver's own hole: the question must not go through the
            // tunnel, or the answer would be the other side's addresses.
            if !resolver_holed {
                for dns in &native_resolvers {
                    if needs_hole(dns.ip()) {
                        let cidr = format!("{}/{}", dns.ip(), host_prefix(dns.ip()));
                        match crate::routing::drill_hole(&cidr, gateway.as_deref(), if_index).await {
                            Ok(hole) => {
                                info!(cidr = %hole.cidr, "bypass: the resolver has a hole");
                                remember_hole(&state, hole).await;
                            }
                            Err(e) => warn!(cidr, error = %e, "bypass: the hole for the resolver was refused"),
                        }
                    }
                }
                resolver_holed = true;
            }

            let mut fresh: Vec<IpAddr> = Vec::new();
            // The names are asked together: the preset carries dozens of them,
            // and one question after another would hold the tunnel hostage
            // for minutes.
            let mut questions: Vec<_> = Vec::with_capacity(domains.len());
            for domain in &domains {
                let native_resolvers = live_resolvers.clone();
                let tunnel_dns = tunnel_dns;
                questions.push(async move {
                    // Two answers: the one the machine's own resolver gives
                    // and the one the tunnel's resolver gives.  The hole
                    // covers both, so the traffic leaves the machine
                    // whichever answer the application took.
                    let mut answers = crate::bypass::resolve_with(
                        &native_resolvers,
                        domain,
                        RESOLVE_TIMEOUT,
                    )
                    .await;
                    let mut ips = answers.addresses.clone();
                    ips.extend(
                        crate::bypass::resolve(tunnel_dns, domain, RESOLVE_TIMEOUT).await,
                    );
                    ips.sort();
                    ips.dedup();
                    answers.addresses = ips;
                    answers
                });
            }
            let answers: Vec<crate::bypass::ResolverAnswers> =
                futures::stream::iter(questions)
                    .buffer_unordered(RESOLVE_PARALLEL)
                    .collect()
                    .await;
            let mut asked: Vec<IpAddr> = Vec::new();
            // How many names each of the machine's resolvers answered.
            let mut counts: Vec<(SocketAddr, usize)> = Vec::new();
            for answer in answers {
                for (server, count) in answer.counts {
                    match counts.iter_mut().find(|(s, _)| *s == server) {
                        Some(entry) => entry.1 += count,
                        None => counts.push((server, count)),
                    }
                }
                if answered_resolver.is_none() {
                    answered_resolver = answer.best;
                }
                asked.extend(answer.addresses);
            }
            for ip in asked {
                if known.insert(ip) {
                    fresh.push(ip);
                }
            }
            info!(
                names = domains.len(),
                addresses = known.len(),
                fresh = fresh.len(),
                resolvers = ?counts,
                "bypass: the names are resolved"
            );
            // A resolver that answered nothing is not asked again: every name
            // would wait for it.
            let answering: Vec<SocketAddr> = counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(server, _)| *server)
                .collect();
            if !answering.is_empty() && answering.len() < live_resolvers.len() {
                info!(
                    dropped = live_resolvers.len() - answering.len(),
                    "bypass: the resolvers that stayed silent are not asked again"
                );
                live_resolvers = answering;
            }
            // The holes are drilled in one go: a route per address, through
            // the routing API of the system -- the way the other clients do
            // it.  One process per hole would take minutes for a hundred
            // names.
            let mut holes: Vec<String> = Vec::with_capacity(fresh.len());
            for ip in &fresh {
                let cidr = format!("{ip}/{}", host_prefix(*ip));
                if crate::bypass::hole_is_safe(&cidr, tunnel_addr) {
                    holes.push(cidr);
                }
            }
            if !holes.is_empty() {
                let drilled =
                    crate::routing::drill_holes_batch(&holes, gateway.as_deref(), if_index).await;
                info!(holes = drilled.len(), "bypass: the holes follow the names");
                for hole in drilled {
                    remember_hole(&state, hole).await;
                }
            }

            // The adapter's resolver: the machine's own, once that resolver
            // has answered a question.  A resolver that stays silent would
            // take the names of the whole machine away -- and a silent
            // resolver is the rule on a line where the provider filters the
            // questions to some of them.
            if !dns_answered && !known.is_empty() {
                if let Some(dns) = answered_resolver {
                    if is_usable_dns(dns) {
                        dns_answered = true;
                        let tun_name = {
                            let s = state.service.lock().await;
                            s.tun_name.clone()
                        };
                        info!(
                            resolver = %dns.ip(),
                            "bypass: the names are answered by the machine's own resolver"
                        );
                        let _ = tokio::process::Command::new("netsh")
                            .args([
                                "interface",
                                "ip",
                                "set",
                                "dns",
                                &tun_name,
                                "static",
                                &dns.ip().to_string(),
                            ])
                            .output()
                            .await;
                    }
                }
            }

            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
        }
        info!("bypass: the watcher stopped");
    });
}

/// Remember a hole: it is the device's own, and it goes when the tunnel goes.
///
/// The hole is a route.  The kill-switch is NOT touched here: the traffic
/// that leaves through a hole leaves through the physical interface, and the
/// kill-switch already lets that interface through.  Rebuilding the filters
/// for every hole would take the firewall down hundreds of times a minute --
/// and the handshake of the tunnel would die in the middle of it.
async fn remember_hole(state: &Arc<AppState>, hole: crate::routing::BypassHole) {
    let mut s = state.service.lock().await;
    s.bypass_holes.push(hole);
}

async fn post_tun_start(
    State(state): State<Arc<AppState>>,
    Json(params): Json<TunStartParams>,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    activate_tun_inner(&state, params, tokio_util::sync::CancellationToken::new())
        .await
        .map_err(map_err)?;
    Ok(StatusCode::OK)
}

async fn post_tun_stop(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let (cancel, active_conns, drain_timeout_secs) = {
        let mut s = state.service.lock().await;

        if s.tun_phase != TunPhase::TunActive {
            return Err(map_err(TunError::NotActive));
        }

        s.tun_phase = TunPhase::Transitioning;

        let cancel = s.ipstack_cancel.take();
        let ac = s.active_conns.clone();
        let dt = s.drain_timeout_secs;
        (cancel, ac, dt)
    };

    // Cancel the token (stops accepting new connections).
    if let Some(ref c) = cancel {
        c.cancel();
    }

    // Drain active connections up to timeout.
    if let Some(ref ac) = active_conns {
        let n = ac.load(std::sync::atomic::Ordering::Relaxed);
        if n > 0 {
            info!("TUN stop: draining {n} active connections...");
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(drain_timeout_secs);
            loop {
                let remaining = ac.load(std::sync::atomic::Ordering::Relaxed);
                if remaining == 0 {
                    info!("TUN stop: drain complete");
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    info!("TUN stop: drain complete ({remaining} connections remained after timeout)");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    let mut s = state.service.lock().await;

    // The applications come back into the tunnel: the driver takes its
    // filters down and its device is closed.
    if let Some(split) = s.split_tunnel.take() {
        drop(split);
        info!("TUN stop: the split-tunnel is disengaged");
    }

    if let Some(mut ks) = s.killswitch.take() {
        let _ = ks.deactivate();
    }

    // Restore routes manually
    let tun_name = s.tun_name.clone();
    if s.tun_default_set {
        let iface = format!("interface={tun_name}");
        let (_, _) = tokio::join!(
            tokio::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "0.0.0.0/1", &iface, "store=active"])
                .output(),
            tokio::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "128.0.0.0/1", &iface, "store=active"])
                .output(),
        );
        s.tun_default_set = false;
    }

    // The IPv6 half-routes go with the IPv4 ones: a route left behind
    // would point the host's IPv6 into an adapter that no longer carries
    // an IPv6 address.  The IPv6 address of the adapter goes with the
    // routes: an address left behind would make the host pick it as the
    // source of traffic that has nowhere to go.
    if let Some(addr) = tunnel_ipv6_addr(state.config.as_ref()) {
        let iface = format!("interface={tun_name}");
        let (_, _) = tokio::join!(
            tokio::process::Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", "::/1", &iface, "store=active"])
                .output(),
            tokio::process::Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", "8000::/1", &iface, "store=active"])
                .output(),
        );

        let name = tun_name.clone();
        let addr_cidr = addr.clone();
        let removed = tokio::task::spawn_blocking(move || {
            crate::wintun::remove_ipv6_address(&name, &addr_cidr)
        })
        .await
        .unwrap_or_else(|e| {
            Err(TunError::Wintun(format!("spawn_blocking panicked: {e}")))
        });
        match removed {
            Ok(()) => info!(addr = %addr, "TUN stop: IPv6 address removed"),
            Err(e) => warn!("TUN stop: IPv6 address {addr} was not removed: {e}"),
        }
    }

    // Remove bypass routes — use same netsh family as add_bypass in routing.rs
    let bypass: Vec<std::net::IpAddr> = s.bypass_addrs.drain(..).collect();
    let if_index = s.if_index;
    for addr in bypass {
        let prefix = format!("{}/32", addr);
        let if_idx_str = if_index.to_string();
        let _ = tokio::process::Command::new("netsh")
            .args([
                "interface", "ipv4", "delete", "route",
                &prefix,
                &format!("interface={if_idx_str}"),
                "store=active",
            ])
            .output()
            .await;
    }

    // Close the holes: the prefixes the person excluded go back to the
    // tunnel.  A hole left behind would keep the traffic of that prefix
    // out of the tunnel with the tunnel off.
    let holes: Vec<crate::routing::BypassHole> = s.bypass_holes.drain(..).collect();
    for hole in &holes {
        crate::routing::close_hole(hole);
    }
    if !holes.is_empty() {
        info!(holes = holes.len(), "TUN stop: the bypass holes are closed");
    }

    // Clear DNS
    let _ = tokio::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dns", &tun_name, "dhcp"])
        .output()
        .await;

    s.socks5_addr = None;
    s.tun_phase = TunPhase::AdapterReady;
    info!("TUN stopped");
    Ok(StatusCode::OK)
}

async fn post_proxy_set(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ProxySetParams>,
) -> StatusCode {
    crate::proxy::set_system_proxy(&params.proxy_server).await;
    let mut s = state.service.lock().await;
    s.proxy_active = Some(params.proxy_server);
    StatusCode::OK
}

async fn post_proxy_clear(
    State(state): State<Arc<AppState>>,
) -> StatusCode {
    crate::proxy::clear_system_proxy().await;
    let mut s = state.service.lock().await;
    s.proxy_active = None;
    StatusCode::OK
}

async fn post_admin_restart(
    State(state): State<Arc<AppState>>,
) -> StatusCode {
    info!("Restart requested via /admin/restart");
    let _ = state.stop_tx.send(());
    StatusCode::OK
}

async fn get_policy(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let config = state.policy.get_config().await;
    // The preset's rules are not shown: they are not the person's rules, and
    // a client that read them and wrote them back would double them.
    let preset_len = crate::preset::Preset::get()
        .map(|preset| preset.policy_rules().len())
        .unwrap_or(0);
    let rules = if preset_len > 0 && config.rules.len() >= preset_len {
        config.rules[..config.rules.len() - preset_len].to_vec()
    } else {
        config.rules.clone()
    };
    Json(serde_json::json!({
        "default_action": config.default_action,
        "rules": rules,
    }))
}

async fn set_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<mirage_tun_core::policy::PolicyConfigRequest>,
) -> StatusCode {
    // The preset's rules go after the ones of whoever pushed the policy:
    // the person's own rule must not be overruled by the preset.
    let mut rules = req.rules.clone();
    if let Some(preset) = crate::preset::Preset::get() {
        rules.extend(preset.policy_rules());
    }
    let compiled = mirage_tun_core::policy::CompiledPolicy::compile(rules, req.default_action.clone());
    // The networks of the preset are NOT permits and NOT holes: a hole is a
    // route, and the list of a country is thousands of prefixes.  They stay
    // in the policy, and the data plane walks out of the tunnel with them.
    let (preset_v4, preset_v6) = crate::preset::Preset::get()
        .map(|preset| preset.cidr_pairs())
        .unwrap_or_default();
    let new_bypass_cidrs: Vec<(u32, u32)> = compiled
        .bypass_cidrs()
        .into_iter()
        .filter(|pair| !preset_v4.contains(pair))
        .collect();
    let new_bypass_cidrs_v6: Vec<(u128, u128)> = compiled
        .bypass_cidrs_v6()
        .into_iter()
        .filter(|pair| !preset_v6.contains(pair))
        .collect();
    state.policy.update(compiled).await;
    info!("Policy updated via API");

    // Re-apply WFP bypass CIDR permits (IPv4 + IPv6) when TUN is active.
    {
        let mut s = state.service.lock().await;
        if s.tun_phase == TunPhase::TunActive {
            let relay_ips: Vec<IpAddr> = s.bypass_addrs.clone();
            let tun_name = s.tun_name.clone();
            if let Some(ks) = s.killswitch.as_mut() {
                if let Err(e) = ks.update_bypass_cidrs(new_bypass_cidrs, new_bypass_cidrs_v6, &relay_ips, &tun_name, &[]) {
                    warn!("WFP bypass CIDR update failed (non-fatal): {e}");
                } else {
                    info!("WFP bypass CIDRs updated (IPv4 + IPv6)");
                }
            }
        }
    }

    // Best-effort persist — failure is logged inside, never fails the response.
    crate::service::save_policy_to_config(&req);
    StatusCode::OK
}

async fn get_chains_list(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let configs = state.chains.to_configs().await;
    Json(serde_json::json!({ "chains": configs }))
}

async fn post_chains_update(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ChainsUpdateParams>,
) -> StatusCode {
    let new_map: ChainMap = params.chains.iter().filter_map(|c| {
        let socks5_addr = c.socks5_addr.parse::<SocketAddr>()
            .map_err(|e| warn!("chains/update: invalid addr '{}' for '{}': {e}", c.socks5_addr, c.name))
            .ok()?;
        let dns_upstream = c.dns_upstream.as_ref().and_then(|d| d.parse::<SocketAddr>().ok());
        Some((c.name.clone(), ChainEntry { chain_id: c.name.clone(), socks5_addr, dns_upstream }))
    }).collect();
    let protocols: HashMap<String, ChainProtocol> = params
        .chains
        .iter()
        .map(|c| (c.name.clone(), c.protocol.clone()))
        .collect();

    let count = new_map.len();
    state.chains.update_with_protocols(new_map, protocols).await;
    info!("Chains updated via API: {count} chains");

    // Best-effort persist — failure is logged inside, never fails the response.
    crate::service::save_chains_to_config(&params.chains);
    StatusCode::OK
}

/// True when the address can be used as a DNS server.
fn is_usable_dns(addr: SocketAddr) -> bool {
    !addr.ip().is_unspecified() && addr.port() != 0
}

/// The IPv6 address the adapter must carry, if any.
///
/// Only the raw-IP mode forwards packets at L3: in the stack mode the
/// userspace TCP/IP stack terminates IPv4 alone, and an IPv6 address on
/// the adapter would pull the host's IPv6 into a stack that cannot carry
/// it.  The address is the one the config names explicitly, or the one
/// derived from the IPv4 address of the tunnel (10.77.0.N -> fd77::N/64).
fn tunnel_ipv6_addr(config: &TunConfig) -> Option<String> {
    if !config.is_raw_ip() {
        return None;
    }
    config.effective_ipv6_addr()
}

async fn discover_native_dns(if_index: u32) -> Option<SocketAddr> {
    // Query DNS servers for the specific interface by index.
    // `netsh interface ipv4 show dnsservers interface=<idx>` returns only the
    // DNS entries for that interface, avoiding picking up 8.8.8.8 that we set
    // on the TUN adapter itself.
    let index_str = if_index.to_string();
    let out = tokio::process::Command::new("netsh")
        .args(["interface", "ipv4", "show", "dnsservers", &format!("interface={index_str}")])
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        // The servers come as a sentence, not as a bare address:
        //   "DNS servers configured through DHCP:  8.8.8.8"
        // A line that is only an address is taken as it is.
        let tail = match trimmed.split_once(':') {
            Some((_, tail)) => tail,
            None => trimmed,
        };
        for token in tail.split_whitespace() {
            if let Ok(ip) = token.parse::<std::net::Ipv4Addr>() {
                return Some(SocketAddr::new(IpAddr::V4(ip), 53));
            }
        }
    }
    // The guess must be one this network answers.  A resolver that stays
    // silent would leave the machine without names -- and the names are
    // what the holes follow.
    info!("native_dns: the interface names no resolver; falling back to 8.8.8.8");
    Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53))
}

/// The resolvers of the machine itself, in the order they are asked.
///
/// The names of the bypass must be resolved the way the machine would
/// resolve them with the tunnel off -- otherwise the hole is drilled for
/// the wrong addresses.  A provider that filters the questions to some
/// resolvers (Google's are filtered on many lines) leaves the machine with
/// a resolver that stays silent, so the gateway is asked too: the router
/// answers for the line it serves.
async fn native_resolvers(
    if_index: u32,
    gateway: Option<&str>,
    pinned: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    let mut push = |server: Option<SocketAddr>, servers: &mut Vec<SocketAddr>| {
        if let Some(server) = server {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    };
    push(pinned, &mut servers);
    if servers.is_empty() {
        push(discover_native_dns(if_index).await, &mut servers);
    }
    // The router is a resolver as often as not, and it is the one that
    // answers when the provider filters the others.
    if let Some(gateway) = gateway {
        if let Ok(ip) = gateway.trim().parse::<std::net::Ipv4Addr>() {
            push(Some(SocketAddr::new(IpAddr::V4(ip), 53)), &mut servers);
        }
    }
    info!(
        servers = servers.len(),
        "bypass: the names are asked of the machine's own resolvers"
    );
    servers
}

async fn get_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let rule_hits = state.metrics.rule_hits();
    let snapshot = state.metrics.snapshot(&rule_hits);
    Json(serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null))
}

/// `GET /connections` — list of active TCP destinations grouped by chain.
/// Used by the launcher to render the live routing tree.
async fn get_connections(State(state): State<Arc<AppState>>) -> Json<Vec<crate::metrics::ConnSnapshot>> {
    Json(state.connections.snapshot())
}

fn map_err(e: TunError) -> (StatusCode, Json<ErrorBody>) {
    match e {
        TunError::AlreadyActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::NotActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::AdapterNotReady => (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorBody { error: e.to_string() })),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error: e.to_string() })),
    }
}
