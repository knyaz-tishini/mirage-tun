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

use crate::error::TunError;
use crate::ipstack::IpStackRunner;
use crate::routing::Routing;
use crate::state::{ServiceState, TunPhase};

#[derive(Deserialize)]
pub struct TunStartParams {
    pub socks5_addr: String,
    #[serde(default)]
    pub relay_addrs: Vec<String>,
    #[serde(default)]
    pub policy: Option<crate::policy::PolicyConfigRequest>,
}

#[derive(Deserialize)]
pub struct ProxySetParams {
    pub proxy_server: String,
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
    let mut s = state.service.lock().await;

    if s.wintun.is_none() {
        return Err(TunError::AdapterNotReady);
    }
    if s.tun_phase == TunPhase::TunActive {
        return Err(TunError::AlreadyActive);
    }

    let socks5_addr: SocketAddr = params.socks5_addr.parse().map_err(|e| {
        TunError::Other(format!("invalid socks5_addr: {e}"))
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

    // Activate WFP kill-switch (needs if_index for native bypass permit)
    let mut killswitch = crate::firewall::WfpKillSwitch::new();
    killswitch.set_native_if_index(if_index);
    if let Err(e) = killswitch.activate(&relay_ips, &tun_name, &[]) {
        warn!("WFP kill-switch failed to activate (non-fatal): {e}");
    }

    let cancel = tokio_util::sync::CancellationToken::new();

    let native_dns = discover_native_dns(if_index).await;
    info!("native_dns resolved: {native_dns:?}");

    let device = crate::wintun::WintunDevice::new(s.wintun.as_ref().unwrap());
    let _runner = IpStackRunner::start(
        device,
        socks5_addr,
        cancel.clone(),
        relay_ips,
        if_index,
        Arc::clone(&state.policy),
        Arc::clone(&state.dns_map),
        native_dns,
    )
    .await?;

    s.ipstack_cancel = Some(cancel);
    s.socks5_addr = Some(socks5_addr);
    s.killswitch = Some(killswitch);
    s.tun_phase = TunPhase::TunActive;
    s.if_index = if_index;

    // Store routing state
    s.original_gateway = routing.original_gateway().map(|s| s.to_owned());
    s.tun_default_set = true;
    // Prevent Drop from restoring routes — we'll do it manually on stop
    std::mem::forget(routing);

    if let Some(policy_req) = params.policy {
        let compiled = crate::policy::CompiledPolicy::compile(policy_req.rules, policy_req.default_action);
        state.policy.update(compiled).await;
        info!("Policy loaded from TUN start params");
    }

    info!("TUN started, socks5={socks5_addr}");
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

    // Remove bypass routes
    let bypass: Vec<String> = s.bypass_routes.drain(..).collect();
    for addr in bypass {
        let _ = tokio::process::Command::new("route")
            .args(["delete", &addr, "mask", "255.255.255.255"])
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
    crate::proxy::set_system_proxy(&params.proxy_server);
    let mut s = state.service.lock().await;
    s.proxy_active = Some(params.proxy_server);
    StatusCode::OK
}

async fn post_proxy_clear(
    State(state): State<Arc<AppState>>,
) -> StatusCode {
    crate::proxy::clear_system_proxy();
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
    let compiled = crate::policy::CompiledPolicy::compile(req.rules, req.default_action);
    state.policy.update(compiled).await;
    info!("Policy updated via API");
    StatusCode::OK
}

async fn discover_native_dns(_if_index: u32) -> Option<SocketAddr> {
    let out = tokio::process::Command::new("netsh")
        .args(["interface", "ip", "show", "dns"])
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
