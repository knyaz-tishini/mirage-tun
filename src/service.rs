use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use tokio::sync::{watch, Mutex};
use tracing::info;

use crate::state::ServiceState;
use crate::wintun::WintunHandle;
use crate::routing::cleanup_stale_routes;

static STOP_TX: OnceLock<watch::Sender<()>> = OnceLock::new();

const TUN_NAME: &str = "mirage0";
const TUN_ADDR: &str = "10.0.85.1/24";
const TUN_MTU: u16 = 1500;
const API_BIND: &str = "127.0.0.1:19485";

windows_service::define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> Result<(), windows_service::Error> {
    windows_service::service_dispatcher::start("mirage2tun", ffi_service_main)?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service_main error: {e}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = watch::channel(());
    STOP_TX.set(stop_tx).ok();

    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service::*;

    let status_handle = service_control_handler::register("mirage2tun", move |control| {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = STOP_TX.get() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(10),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(run_service_logic(status_handle, stop_rx))?;
    Ok(())
}

pub async fn run_service_logic(
    _status_handle: impl std::any::Any,
    mut stop_rx: watch::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Stale state cleanup
    cleanup_stale_routes(TUN_NAME);
    crate::proxy::clear_system_proxy();

    let wintun = match WintunHandle::create(TUN_NAME, TUN_ADDR, TUN_MTU).await {
        Ok(w) => {
            info!("Wintun adapter '{TUN_NAME}' ready");
            Some(w)
        }
        Err(e) => {
            tracing::error!("Failed to create Wintun adapter: {e}");
            None
        }
    };

    let mut state = ServiceState::new(TUN_NAME.to_owned());
    state.wintun = wintun;
    let state = Arc::new(Mutex::new(state));

    let router = crate::api::build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(API_BIND).await?;
    info!("Management API listening on {API_BIND}");

    tokio::select! {
        result = axum::serve(listener, router) => {
            if let Err(e) = result {
                tracing::error!("API server error: {e}");
            }
        }
        _ = stop_rx.changed() => {
            info!("Stop signal received");
        }
    }

    // Graceful shutdown
    {
        let mut s = state.lock().await;
        if let Some(cancel) = s.ipstack_cancel.take() {
            cancel.cancel();
        }
        if s.tun_default_set {
            let name = &s.tun_name;
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "0.0.0.0/1", &format!("interface={name}"), "store=active"])
                .output();
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "128.0.0.0/1", &format!("interface={name}"), "store=active"])
                .output();
        }
        if s.proxy_active.is_some() {
            crate::proxy::clear_system_proxy();
        }
        s.wintun = None;
    }

    info!("Service stopped");
    Ok(())
}
