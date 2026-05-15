use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mirage_tun_core::chains::{ChainConfig, ChainEntry, ChainMap, ChainRegistry};

use crate::metrics::MetricsRegistry;

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
) {
    let state = Arc::new(AppState { metrics, chains });
    let router = Router::new()
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics))
        .route("/chains/list", get(get_chains_list))
        .route("/chains/update", post(post_chains_update))
        .with_state(state);

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
            Some((c.name.clone(), ChainEntry { socks5_addr, dns_upstream }))
        })
        .collect();

    let count = new_map.len();
    state.chains.update(new_map).await;
    info!("chains updated via API: {count} chains");

    StatusCode::OK
}
