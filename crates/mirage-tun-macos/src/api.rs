use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Json, Router,
};
use mirage_tun_core::metrics::StackMetrics;
use tokio_util::sync::CancellationToken;
use tracing::info;

struct AppState {
    metrics: Arc<StackMetrics>,
}

pub async fn serve(bind: SocketAddr, metrics: Arc<StackMetrics>, cancel: CancellationToken) {
    let state = Arc::new(AppState { metrics });
    let router = Router::new()
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics))
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
