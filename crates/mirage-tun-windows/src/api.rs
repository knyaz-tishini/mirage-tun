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

    let t0 = std::time::Instant::now();

    let raw_ip_mode = state.config.is_raw_ip();

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
    crate::bypass::log_plan(&plan);

    // The resolver the machine had before the tunnel gets a hole too: the
    // names must be answered the way the person sees them, or the addresses
    // the application uses are not the addresses the hole covers.
    if let Some(dns) = native_dns {
        if needs_hole(dns.ip()) {
            let cidr = format!("{}/{}", dns.ip(), host_prefix(dns.ip()));
            if let Err(e) = routing.add_bypass_cidr(&cidr).await {
                warn!(cidr, "activate: the hole for the resolver was refused: {e}");
            }
        }
    }

    // The networks: a hole each.
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

    // The names: a hole for every address the name points at.
    let mut domain_ips: BTreeSet<IpAddr> = BTreeSet::new();
    for domain in &plan.domains {
        let ips = crate::bypass::resolve_both(native_dns, None, domain, RESOLVE_TIMEOUT).await;
        if ips.is_empty() {
            warn!(domain, "activate: the name has no address yet; the hole follows it later");
        }
        domain_ips.extend(ips);
    }
    for ip in &domain_ips {
        let cidr = format!("{ip}/{}", host_prefix(*ip));
        if let Err(e) = routing.add_bypass_cidr(&cidr).await {
            warn!(cidr, "activate: the bypass hole was refused: {e}");
        }
    }
    if !plan.cidrs.is_empty() || !plan.domains.is_empty() {
        info!(
            networks = plan.cidrs.len(),
            names = plan.domains.len(),
            addresses = domain_ips.len(),
            "activate: the bypass holes are in place"
        );
    }

    // The resolver the adapter asks.
    //
    // When the person excluded names, the names must be answered the way
    // they answered before the tunnel: the application then takes the
    // addresses the hole covers, and the question itself does not have to
    // go through the tunnel.  The machine's own resolver is the one that
    // answers that way -- but only if it answers at all: a resolver that
    // stays silent would leave the machine without names.
    let dns_ip = if !plan.domains.is_empty() && !domain_ips.is_empty() {
        match native_dns {
            Some(dns) if is_usable_dns(dns) => {
                info!(
                    resolver = %dns.ip(),
                    "activate: the names are answered by the machine's own resolver"
                );
                dns.ip().to_string()
            }
            _ => state.config.dns_upstream.ip().to_string(),
        }
    } else if raw_ip_mode && !is_usable_dns(state.config.dns_upstream) {
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

    // The names are holes that follow the name: the addresses of a CDN
    // change under it, so the holes are drilled again and again while the
    // tunnel is up.
    if !plan.domains.is_empty() {
        spawn_bypass_watcher(
            Arc::clone(state),
            plan.domains.clone(),
            native_dns,
            state.config.dns_upstream,
            gateway,
            if_index,
            plan.cidrs.clone(),
            domain_ips.clone(),
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
    native_dns: Option<SocketAddr>,
    tunnel_dns: SocketAddr,
    gateway: Option<String>,
    if_index: u32,
    plan_cidrs: Vec<String>,
    known: BTreeSet<IpAddr>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let interval = Duration::from_secs(state.config.bypass_refresh_secs.max(5));
    tokio::spawn(async move {
        let mut known = known;
        info!(
            names = domains.len(),
            every = interval.as_secs(),
            "bypass: the watcher is watching the names"
        );
        loop {
            for domain in &domains {
                // Two answers: the one the machine's own resolver gives and
                // the one the tunnel's resolver gives.  The hole covers both,
                // so the traffic leaves the machine whichever answer the
                // application took.
                let ips = crate::bypass::resolve_both(
                    native_dns,
                    Some(tunnel_dns),
                    domain,
                    RESOLVE_TIMEOUT,
                )
                .await;
                for ip in ips {
                    if !known.insert(ip) {
                        continue;
                    }
                    let cidr = format!("{ip}/{}", host_prefix(ip));
                    match crate::routing::drill_hole(&cidr, gateway.as_deref(), if_index).await {
                        Ok(hole) => {
                            info!(cidr = %hole.cidr, domain, "bypass: the hole follows the name");
                            let mut s = state.service.lock().await;
                            s.bypass_holes.push(hole);
                            let permits = wfp_permits(&plan_cidrs, &s.bypass_holes);
                            let relay_ips: Vec<IpAddr> = s.bypass_addrs.clone();
                            let tun_name = s.tun_name.clone();
                            if let Some(ks) = s.killswitch.as_mut() {
                                if let Err(e) = ks.update_bypass_cidrs(
                                    permits.0,
                                    permits.1,
                                    &relay_ips,
                                    &tun_name,
                                    &[],
                                ) {
                                    warn!("WFP bypass permit update failed (non-fatal): {e}");
                                }
                            }
                        }
                        Err(e) => warn!(cidr, error = %e, "bypass: the hole was refused"),
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

/// The addresses the kill-switch must let through: the networks the person
/// excluded and every hole that was drilled.
fn wfp_permits(
    plan_cidrs: &[String],
    holes: &[crate::routing::BypassHole],
) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let mut v4: Vec<(u32, u32)> = Vec::new();
    let mut v6: Vec<(u128, u128)> = Vec::new();
    for cidr in plan_cidrs {
        if let Some(v) = crate::bypass::cidr_to_wfp(cidr) {
            v4.push(v);
        }
        if let Some(v) = crate::bypass::cidr_to_wfp_v6(cidr) {
            v6.push(v);
        }
    }
    for hole in holes {
        if let Some(v) = crate::bypass::cidr_to_wfp(&hole.cidr) {
            v4.push(v);
        }
        if let Some(v) = crate::bypass::cidr_to_wfp_v6(&hole.cidr) {
            v6.push(v);
        }
    }
    (v4, v6)
}

async fn post_tun_start(
    State(state): State<Arc<AppState>>,
    Json(params): Json<TunStartParams>,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    activate_tun_inner(&state, params).await.map_err(map_err)?;
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
    Json(serde_json::json!({
        "default_action": config.default_action,
        "rules": config.rules,
    }))
}

async fn set_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<mirage_tun_core::policy::PolicyConfigRequest>,
) -> StatusCode {
    let compiled = mirage_tun_core::policy::CompiledPolicy::compile(req.rules.clone(), req.default_action.clone());
    let new_bypass_cidrs = compiled.bypass_cidrs();
    let new_bypass_cidrs_v6 = compiled.bypass_cidrs_v6();
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
