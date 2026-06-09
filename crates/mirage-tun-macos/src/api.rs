use std::net::SocketAddr;
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
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::chains::{ChainConfig, ChainEntry, ChainMap, ChainRegistry};

use crate::metrics::MetricsRegistry;

/// Emitted at most once across the process lifetime.
static UNAUTHED_WARNED: OnceLock<()> = OnceLock::new();

#[derive(Deserialize)]
struct ChainsUpdateParams {
    chains: Vec<ChainConfig>,
}

struct AppState {
    metrics: Arc<MetricsRegistry>,
    chains: Arc<ChainRegistry>,
}

pub async fn serve(
    bind: SocketAddr,
    metrics: Arc<MetricsRegistry>,
    chains: Arc<ChainRegistry>,
    cancel: CancellationToken,
    api_key: Option<String>,
) {
    let state = Arc::new(AppState { metrics, chains });

    // Routes always open (unauthenticated health/metrics scrapers).
    let open = Router::new()
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics));

    // Guarded routes require auth when api_key is set.
    let guarded = Router::new()
        .route("/chains/list", get(get_chains_list))
        .route("/chains/update", post(post_chains_update));

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

    info!(addr = %bind, "metrics API listening");

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
