use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::chains::{ChainConfig, ChainEntry, ChainMap, ChainRegistry};
use mirage_tun_core::policy::{CompiledPolicy, PolicyConfigRequest, PolicyEngine};

use crate::conn_registry::ConnectionRegistry;
use crate::firewall::MacosFirewall;
use crate::metrics::MetricsRegistry;
use crate::routing::MacosRouting;

/// Emitted at most once across the process lifetime.
static UNAUTHED_WARNED: OnceLock<()> = OnceLock::new();

#[derive(Deserialize)]
struct ChainsUpdateParams {
    chains: Vec<ChainConfig>,
}

struct AppState {
    metrics: Arc<MetricsRegistry>,
    chains: Arc<ChainRegistry>,
    connections: Arc<ConnectionRegistry>,
    /// Live policy engine — updated atomically by `/policy/set`.
    policy: Arc<PolicyEngine>,
    /// pf anchor manager — reloaded on bypass-CIDR change.
    firewall: Arc<Mutex<MacosFirewall>>,
    /// Routing state — bypass net routes diff-applied on policy change.
    routing: Arc<Mutex<MacosRouting>>,
    /// Relay addresses currently in use (needed to rebuild pf rules).
    relay_addrs: Vec<IpAddr>,
    /// TUN interface name (e.g. "utun3") — needed to rebuild pf rules.
    tun_name: String,
    /// smoltcp ip_filter bypass table (IPv4) — hot-reloadable.
    bypass_v4_filter: Arc<std::sync::RwLock<Vec<(u32, u32)>>>,
    /// smoltcp ip_filter bypass table (IPv6) — hot-reloadable.
    bypass_v6_filter: Arc<std::sync::RwLock<Vec<(u128, u128)>>>,
}

pub async fn serve(
    bind: SocketAddr,
    metrics: Arc<MetricsRegistry>,
    chains: Arc<ChainRegistry>,
    connections: Arc<ConnectionRegistry>,
    policy: Arc<PolicyEngine>,
    firewall: Arc<Mutex<MacosFirewall>>,
    routing: Arc<Mutex<MacosRouting>>,
    relay_addrs: Vec<IpAddr>,
    tun_name: String,
    bypass_v4_filter: Arc<std::sync::RwLock<Vec<(u32, u32)>>>,
    bypass_v6_filter: Arc<std::sync::RwLock<Vec<(u128, u128)>>>,
    cancel: CancellationToken,
    api_key: Option<String>,
) {
    let state = Arc::new(AppState {
        metrics,
        chains,
        connections,
        policy,
        firewall,
        routing,
        relay_addrs,
        tun_name,
        bypass_v4_filter,
        bypass_v6_filter,
    });

    // Routes always open (unauthenticated health/metrics scrapers).
    let open = Router::new()
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics));

    // Guarded routes require auth when api_key is set.
    let guarded = Router::new()
        .route("/chains/list", get(get_chains_list))
        .route("/chains/update", post(post_chains_update))
        .route("/connections", get(get_connections))
        .route("/policy/get", get(get_policy))
        .route("/policy/set", post(set_policy));

    let guarded = match api_key {
        Some(key) => {
            let key = Arc::new(key);
            guarded.layer(middleware::from_fn_with_state(key, bearer_gate))
        }
        None => {
            UNAUTHED_WARNED.get_or_init(|| {
                warn!(
                    "TUN control API is unauthenticated — set `api_key` in config to enable Bearer enforcement"
                );
            });
            guarded
        }
    };

    let router = open.merge(guarded).with_state(state);

    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %bind, err = %e, "API server bind failed");
            return;
        }
    };

    info!(addr = %bind, "macOS TUN control API listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
        .unwrap_or_else(|e| tracing::warn!(err = %e, "API server exited"));
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

async fn get_metrics(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let snap = state.metrics.snapshot();
    Json(serde_json::to_value(snap).unwrap_or(serde_json::Value::Null))
}

async fn get_chains_list(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let configs = state.chains.to_configs().await;
    Json(serde_json::json!({ "chains": configs }))
}

async fn get_connections(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let snaps = state.connections.snapshot();
    Json(serde_json::json!({ "connections": snaps }))
}

async fn post_chains_update(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ChainsUpdateParams>,
) -> StatusCode {
    let new_map: ChainMap = params
        .chains
        .iter()
        .filter_map(|c| {
            let socks5_addr = c
                .socks5_addr
                .parse::<SocketAddr>()
                .map_err(|e| {
                    warn!(
                        "chains/update: invalid addr '{}' for '{}': {e}",
                        c.socks5_addr, c.name
                    )
                })
                .ok()?;
            let dns_upstream = c
                .dns_upstream
                .as_ref()
                .and_then(|d| d.parse::<SocketAddr>().ok());
            Some((c.name.clone(), ChainEntry { chain_id: c.name.clone(), socks5_addr, dns_upstream }))
        })
        .collect();

    let count = new_map.len();
    state.chains.update(new_map).await;
    info!("chains updated via API: {count} chains");

    StatusCode::OK
}

/// `GET /policy/get` — return the current compiled policy (rules + default_action).
///
/// Wire-identical to the Windows TUN `/policy/get` endpoint.
async fn get_policy(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let config = state.policy.get_config().await;
    Json(serde_json::json!({
        "default_action": config.default_action,
        "rules": config.rules,
    }))
}

/// `POST /policy/set` — push a new routing policy and apply it LIVE.
///
/// Accepts the same `PolicyConfigRequest` JSON as the Windows TUN so that
/// `mirage2app/crates/client-core/src/health_watcher.rs` (which POSTs to
/// `{tun_api_url}/policy/set`) works unchanged on both platforms.
///
/// On receipt:
/// 1. Recompiles the policy (`CompiledPolicy::compile`).
/// 2. Atomically swaps it into the live `PolicyEngine` — the TCP accept loop and
///    DNS routing path snapshot the engine on each flow, so the new policy takes
///    effect on the next connection without a TUN restart.
/// 3. Diffs old vs new bypass CIDRs and applies the delta LIVE:
///    - `MacosRouting::update_bypass_nets` → `route add/delete` via original gw.
///    - `MacosFirewall::reload_bypass_nets` → `pfctl -f` reloads the pf anchor.
///    - smoltcp ip_filter tables updated in-place (sync write lock, non-blocking).
///
/// Wire shape is byte-identical to Windows `/policy/set`.
async fn set_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PolicyConfigRequest>,
) -> StatusCode {
    // 1. Recompile.
    let compiled = CompiledPolicy::compile(req.rules.clone(), req.default_action.clone());
    let new_bypass_cidr_strings = compiled.bypass_cidr_strings();
    let new_bypass_v4 = compiled.bypass_cidrs();
    let new_bypass_v6 = compiled.bypass_cidrs_v6();

    // 2. Swap into the live engine — takes effect for all new flows immediately.
    state.policy.update(compiled).await;
    info!("Policy updated via /policy/set");

    // 3a. Live-diff routing bypass routes (route add/delete via original gw).
    {
        let mut routing = state.routing.lock().await;
        if let Err(e) = routing.update_bypass_nets(new_bypass_cidr_strings.clone()).await {
            warn!("policy/set: routing bypass update failed (non-fatal): {e}");
        }
    }

    // 3b. Reload pf anchor with new bypass CIDRs (atomic pfctl -f replace).
    {
        let mut fw = state.firewall.lock().await;
        if let Err(e) = fw.reload_bypass_nets(
            new_bypass_cidr_strings,
            &state.relay_addrs,
            &state.tun_name,
        ) {
            warn!("policy/set: pf anchor reload failed (non-fatal): {e}");
        }
    }

    // 3c. Update the smoltcp ip_filter bypass tables so newly bypassed CIDRs are
    // excluded from smoltcp interception on the very next packet (belt-and-suspenders
    // parity with routing + pf update above). Write-lock is sync and non-blocking.
    if let Ok(mut guard) = state.bypass_v4_filter.write() {
        *guard = new_bypass_v4;
    }
    if let Ok(mut guard) = state.bypass_v6_filter.write() {
        *guard = new_bypass_v6;
    }

    StatusCode::OK
}
