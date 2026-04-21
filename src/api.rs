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

use mirage_dns::{DnsConfig, DnsResolver};
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
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub struct AppState {
    pub service: Arc<Mutex<ServiceState>>,
    pub stop_tx: watch::Sender<()>,
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
        .with_state(state)
}

async fn get_health() -> StatusCode {
    StatusCode::OK
}

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Json<StatusResponse> {
    let s = state.service.lock().await;
    Json(StatusResponse {
        adapter_alive: s.wintun.is_some(),
        tun_phase: s.tun_phase.clone(),
        proxy_active: s.proxy_active.clone(),
        socks5_addr: s.socks5_addr.map(|a| a.to_string()),
    })
}

async fn post_tun_start(
    State(state): State<Arc<AppState>>,
    Json(params): Json<TunStartParams>,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let mut s = state.service.lock().await;

    if s.wintun.is_none() {
        return Err(map_err(TunError::AdapterNotReady));
    }
    if s.tun_phase == TunPhase::TunActive {
        return Err(map_err(TunError::AlreadyActive));
    }

    let socks5_addr: SocketAddr = params.socks5_addr.parse().map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(ErrorBody { error: format!("invalid socks5_addr: {e}") }))
    })?;

    s.tun_phase = TunPhase::Transitioning;

    let tun_name = s.tun_name.clone();

    // Set DNS on adapter
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dns", &tun_name, "static", "10.0.85.1"])
        .output();

    // Routes AFTER adapter exists — otherwise they vanish with destroyed interface
    let mut routing = Routing::new(&tun_name);
    routing.set_default_route().map_err(map_err)?;

    let mut relay_ips: Vec<IpAddr> = Vec::new();
    for relay in &params.relay_addrs {
        if let Ok(ip) = relay.parse::<IpAddr>() {
            routing.add_bypass(ip).map_err(map_err)?;
            relay_ips.push(ip);
        }
    }

    // Activate WFP kill-switch
    let mut killswitch = crate::firewall::WfpKillSwitch::new();
    if let Err(e) = killswitch.activate(&relay_ips, &tun_name, &[]) {
        warn!("WFP kill-switch failed to activate (non-fatal): {e}");
    }

    let cancel = tokio_util::sync::CancellationToken::new();

    let if_index = routing.original_interface_idx().unwrap_or(0);

    let dns_config = DnsConfig {
        doh_url: "https://1.1.1.1/dns-query".into(),
        http_proxy: Some("http://127.0.0.1:19481".into()),
        cache_size: 4096,
        timeout: std::time::Duration::from_secs(5),
        fallback_dns: "8.8.8.8:53".parse().unwrap(),
    };
    let dns_resolver = DnsResolver::new(dns_config).map_err(|e| {
        map_err(TunError::Routing(format!("DNS resolver init failed: {e}")))
    })?;

    let device = crate::wintun::WintunDevice::new(s.wintun.as_ref().unwrap());
    let _runner = IpStackRunner::start(device, socks5_addr, cancel.clone(), relay_ips, if_index, dns_resolver)
        .await
        .map_err(map_err)?;

    s.ipstack_cancel = Some(cancel);
    s.socks5_addr = Some(socks5_addr);
    s.killswitch = Some(killswitch);
    s.tun_phase = TunPhase::TunActive;

    // Store routing state
    s.original_gateway = routing.original_gateway().map(|s| s.to_owned());
    s.tun_default_set = true;
    // Prevent Drop from restoring routes — we'll do it manually on stop
    std::mem::forget(routing);

    info!("TUN started, socks5={socks5_addr}");
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
        let _ = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "delete", "route", "0.0.0.0/1", &format!("interface={tun_name}"), "store=active"])
            .output();
        let _ = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "delete", "route", "128.0.0.0/1", &format!("interface={tun_name}"), "store=active"])
            .output();
        s.tun_default_set = false;
    }

    // Remove bypass routes
    for addr in s.bypass_routes.drain(..) {
        let _ = std::process::Command::new("route")
            .args(["delete", &addr, "mask", "255.255.255.255"])
            .output();
    }

    // Clear DNS
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dns", &tun_name, "dhcp"])
        .output();

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

fn map_err(e: TunError) -> (StatusCode, Json<ErrorBody>) {
    match e {
        TunError::AlreadyActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::NotActive => (StatusCode::CONFLICT, Json(ErrorBody { error: e.to_string() })),
        TunError::AdapterNotReady => (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorBody { error: e.to_string() })),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody { error: e.to_string() })),
    }
}
