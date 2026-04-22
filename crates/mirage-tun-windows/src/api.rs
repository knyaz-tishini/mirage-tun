use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

use mirage_tun_core::traits::PlatformFirewall;

use crate::chains::{ChainConfig, ChainMap, ChainRegistry};
use crate::error::TunError;
use crate::ipstack::IpStackRunner;
use crate::routing::Routing;
use crate::state::{ServiceState, TunPhase};

#[derive(Serialize, Deserialize)]
pub struct TunStartParams {
    /// Legacy single-proxy address. Used when `chains` is empty.
    #[serde(default)]
    pub socks5_addr: String,
    #[serde(default)]
    pub relay_addrs: Vec<String>,
    #[serde(default)]
    pub policy: Option<crate::policy::PolicyConfigRequest>,
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
    pub policy: Arc<crate::policy::PolicyEngine>,
    pub dns_map: Arc<crate::dns_map::DnsMap>,
    pub chains: Arc<ChainRegistry>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(get_health))
        .route("/status", get(get_status))
        .route("/tun/start", post(post_tun_start))
        .route("/tun/stop", post(post_tun_stop))
        .route("/proxy/set", post(post_proxy_set))
        .route("/proxy/clear", post(post_proxy_clear))
        .route("/admin/restart", post(post_admin_restart))
        .route("/policy/get", get(get_policy))
        .route("/policy/set", post(set_policy))
        .route("/chains/list", get(get_chains_list))
        .route("/chains/update", post(post_chains_update))
        .with_state(state)
}

async fn get_health() -> StatusCode {
    StatusCode::OK
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
        vec![ChainConfig { name: "default".to_owned(), socks5_addr: params.socks5_addr.clone() }]
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

    // Point adapter DNS at 8.8.8.8 so Windows sends DNS queries into TUN
    // (our udp_dns_loop intercepts them and forwards via SOCKS5)
    let _ = tokio::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dns", &tun_name, "static", "8.8.8.8"])
        .output()
        .await;

    // Routes AFTER adapter exists — otherwise they vanish with destroyed interface
    let mut routing = Routing::new(&tun_name);
    routing.set_default_route().await?;
    info!("activate: set_default_route = {}ms", t0.elapsed().as_millis());

    let mut relay_ips: Vec<IpAddr> = Vec::new();
    for relay in &params.relay_addrs {
        if let Ok(ip) = relay.parse::<IpAddr>() {
            routing.add_bypass(ip).await?;
            relay_ips.push(ip);
        }
    }
    info!("activate: bypass routes = {}ms", t0.elapsed().as_millis());

    let if_index = routing.original_interface_idx().unwrap_or(0);

    // Compile policy from params early so we can extract bypass CIDRs for WFP.
    let initial_policy = params.policy.map(|policy_req| {
        crate::policy::CompiledPolicy::compile(policy_req.rules, policy_req.default_action)
    });
    let bypass_cidrs_for_wfp: Vec<(u32, u32)> = initial_policy
        .as_ref()
        .map(|p| p.bypass_cidrs())
        .unwrap_or_default();

    // Activate WFP kill-switch (needs if_index for native bypass permit).
    // TUN interface index was resolved via spawn_blocking before taking the mutex.
    let mut killswitch = crate::firewall::WfpKillSwitch::new();
    killswitch.set_native_if_index(if_index);
    if let Some(tun_idx) = pre_resolved_tun_idx {
        killswitch.set_tun_if_index(tun_idx);
    }
    killswitch.set_bypass_cidrs(bypass_cidrs_for_wfp);
    if let Err(e) = killswitch.activate(&relay_ips, &tun_name, &[]) {
        warn!("WFP kill-switch failed to activate (non-fatal): {e}");
    }

    let cancel = tokio_util::sync::CancellationToken::new();

    let native_dns = discover_native_dns(if_index).await;
    info!("native_dns resolved: {native_dns:?}");

    let process_resolver = Arc::new(crate::process_info::ProcessResolver::new());

    // Populate the shared chain registry BEFORE starting the ipstack so that
    // IpStackRunner holds a live Arc<ChainRegistry> and always sees current chains.
    let new_map: ChainMap = chain_configs.iter().filter_map(|c| {
        c.socks5_addr.parse::<SocketAddr>().ok().map(|addr| (c.name.clone(), addr))
    }).collect();
    state.chains.update(new_map).await;

    let bypass_addrs_store = relay_ips.clone();
    let device = crate::wintun::WintunDevice::new(s.wintun.as_ref().unwrap());
    let _runner = IpStackRunner::start(
        device,
        Arc::clone(&state.chains),
        cancel.clone(),
        relay_ips,
        if_index,
        Arc::clone(&state.policy),
        Arc::clone(&state.dns_map),
        native_dns,
        process_resolver,
    )
    .await?;

    s.ipstack_cancel = Some(cancel);
    s.socks5_addr = Some(default_socks5);
    s.killswitch = Some(killswitch);
    s.tun_phase = TunPhase::TunActive;
    s.if_index = if_index;
    s.chains = Arc::clone(&state.chains);

    // Store routing state
    s.original_gateway = routing.original_gateway().map(|s| s.to_owned());
    s.tun_default_set = true;
    s.bypass_addrs = bypass_addrs_store;
    // Prevent Drop from restoring routes — we'll do it manually on stop
    std::mem::forget(routing);

    if let Some(compiled) = initial_policy {
        state.policy.update(compiled).await;
        info!("Policy loaded from TUN start params");
    }

    info!("TUN started, default_socks5={default_socks5}, chains={}", chain_configs.len());
    Ok(())
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
    let mut s = state.service.lock().await;

    if s.tun_phase != TunPhase::TunActive {
        return Err(map_err(TunError::NotActive));
    }

    s.tun_phase = TunPhase::Transitioning;

    if let Some(cancel) = s.ipstack_cancel.take() {
        cancel.cancel();
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
                .output()
        );
        s.tun_default_set = false;
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
    Json(req): Json<crate::policy::PolicyConfigRequest>,
) -> StatusCode {
    let compiled = crate::policy::CompiledPolicy::compile(req.rules.clone(), req.default_action.clone());
    let new_bypass_cidrs = compiled.bypass_cidrs();
    state.policy.update(compiled).await;
    info!("Policy updated via API");

    // Re-apply WFP bypass CIDR permits when TUN is active.
    {
        let mut s = state.service.lock().await;
        if s.tun_phase == TunPhase::TunActive {
            let relay_ips: Vec<IpAddr> = s.bypass_addrs.clone();
            let tun_name = s.tun_name.clone();
            if let Some(ks) = s.killswitch.as_mut() {
                if let Err(e) = ks.update_bypass_cidrs(new_bypass_cidrs, &relay_ips, &tun_name, &[]) {
                    warn!("WFP bypass CIDR update failed (non-fatal): {e}");
                } else {
                    info!("WFP bypass CIDRs updated");
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
        c.socks5_addr.parse::<SocketAddr>()
            .map_err(|e| warn!("chains/update: invalid addr '{}' for '{}': {e}", c.socks5_addr, c.name))
            .ok()
            .map(|addr| (c.name.clone(), addr))
    }).collect();

    let count = new_map.len();
    state.chains.update(new_map).await;
    info!("Chains updated via API: {count} chains");

    // Best-effort persist — failure is logged inside, never fails the response.
    crate::service::save_chains_to_config(&params.chains);
    StatusCode::OK
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
        if let Ok(ip) = trimmed.parse::<std::net::Ipv4Addr>() {
            return Some(SocketAddr::new(IpAddr::V4(ip), 53));
        }
    }
    // Fallback to Cloudflare DNS
    Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53))
}

fn map_err(e: TunError) -> (StatusCode, Json<ErrorBody>) {
    match e {
        TunError::AlreadyActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::NotActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::AdapterNotReady => (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorBody { error: e.to_string() })),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error: e.to_string() })),
    }
}
