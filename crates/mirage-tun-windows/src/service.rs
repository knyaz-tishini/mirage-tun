use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::{watch, Mutex};
use tracing::info;
use windows_service::service_control_handler::ServiceStatusHandle;

use crate::api::AppState;
use crate::state::ServiceState;
use crate::wintun::WintunHandle;
use crate::routing::cleanup_stale_routes;

static STOP_TX: OnceLock<watch::Sender<()>> = OnceLock::new();

const TUN_NAME: &str = "mirage0";
const TUN_ADDR: &str = "10.0.85.1/24";
const TUN_MTU: u16 = 1500;
const API_BIND: &str = "127.0.0.1:19485";

fn find_config() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let beside_exe = exe
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("tun.json");
        if beside_exe.exists() {
            return Some(beside_exe);
        }
    }
    let prog_data = PathBuf::from(r"C:\ProgramData\mirage2tun\tun.json");
    if prog_data.exists() {
        return Some(prog_data);
    }
    None
}

async fn autostart_activate(
    state: Arc<crate::api::AppState>,
    params: crate::api::TunStartParams,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::api::activate_tun_inner(&state, params).await?;

    let s = state.service.lock().await;
    if let Some(socks5) = s.socks5_addr {
        let if_index = s.if_index;
        drop(s);
        crate::ipstack::dns_warmup(socks5, if_index).await;
    }
    Ok(())
}

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

    // Init tracing to file before entering async context
    std::fs::create_dir_all("C:\\ProgramData\\mirage2tun\\logs").ok();
    let file_appender = tracing_appender::rolling::daily(
        "C:\\ProgramData\\mirage2tun\\logs",
        "mirage2tun.log",
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter("info,mirage2tun::ipstack=debug,netstack_smoltcp=debug")
        .init();

    // Retrieve stop_tx from OnceLock to pass into logic
    // SAFETY: we just set it above; get() will always succeed here.
    let stop_tx = STOP_TX.get().expect("STOP_TX set above in same function").clone();

    rt.block_on(run_service_logic(Some(status_handle), stop_tx, stop_rx))?;
    Ok(())
}

pub async fn run_service_logic(
    status_handle: Option<ServiceStatusHandle>,
    stop_tx: watch::Sender<()>,
    mut stop_rx: watch::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Stale state cleanup
    cleanup_stale_routes(TUN_NAME).await;
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

    let policy = Arc::new(crate::policy::PolicyEngine::mirage_only());
    let dns_map = Arc::new(crate::dns_map::DnsMap::new());

    let mut svc_state = ServiceState::new(TUN_NAME.to_owned());
    svc_state.wintun = wintun;
    svc_state.policy = Some(Arc::clone(&policy));
    svc_state.dns_map = Arc::clone(&dns_map);
    let svc_state = Arc::new(Mutex::new(svc_state));

    let app_state = Arc::new(AppState {
        service: Arc::clone(&svc_state),
        stop_tx,
        policy,
        dns_map,
    });

    let router = crate::api::build_router(Arc::clone(&app_state));
    let listener = tokio::net::TcpListener::bind(API_BIND).await?;
    info!("Management API listening on {API_BIND}");

    // Autostart TUN if config exists
    {
        let autostart_state = Arc::clone(&app_state);
        tokio::spawn(async move {
            if let Some(config_path) = find_config() {
                info!("Autostart: found config at {}", config_path.display());
                match std::fs::read_to_string(&config_path) {
                    Ok(contents) => {
                        match serde_json::from_str::<crate::api::TunStartParams>(&contents) {
                            Ok(params) => {
                                match autostart_activate(autostart_state, params).await {
                                    Ok(()) => info!("Autostart: TUN activated successfully"),
                                    Err(e) => tracing::warn!("Autostart: TUN activation failed: {e}"),
                                }
                            }
                            Err(e) => tracing::warn!("Autostart: invalid config: {e}"),
                        }
                    }
                    Err(e) => tracing::warn!("Autostart: failed to read config: {e}"),
                }
            } else {
                info!("Autostart: no tun.json found, waiting for API call");
            }
        });
    }

    // Report Running to SCM after successful bind
    if let Some(ref handle) = status_handle {
        use windows_service::service::*;
        handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;
        info!("Reported Running to SCM");
    }

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
        let mut s = svc_state.lock().await;
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

    // Report Stopped to SCM
    if let Some(ref handle) = status_handle {
        use windows_service::service::*;
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
    }

    Ok(())
}
