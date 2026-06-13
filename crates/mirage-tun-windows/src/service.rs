use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::{watch, Mutex};
use tracing::info;
use windows_service::service_control_handler::ServiceStatusHandle;

use crate::api::AppState;
use crate::config::TunConfig;
use crate::metrics::MetricsRegistry;
use crate::state::ServiceState;
use crate::wintun::WintunHandle;
use crate::routing::cleanup_stale_routes;

static STOP_TX: OnceLock<watch::Sender<()>> = OnceLock::new();

const TUN_MTU: u16 = 1500;

pub(crate) fn find_config() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let beside_exe = exe
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("tun.json");
        if beside_exe.exists() {
            return Some(beside_exe);
        }
    }
    // D9 note: the C:\ProgramData\mirage2tun path is install-time and tied to
    // the SCM service name "mirage2tun".  Renaming the path half (ProgramData dir +
    // service name + dispatcher names in service.rs:132/149 + bin/mirage2tun.rs:244/305)
    // requires a coordinated install-time rename of the service registration and is
    // deferred to a separate task.  The adapter name (mirage0) and tunnel-type string
    // ("Mirage") are already configurable via TunConfig::tun_name / tunnel_type (D9
    // adapter-naming half — done).
    let prog_data = PathBuf::from(r"C:\ProgramData\mirage2tun\tun.json");
    if prog_data.exists() {
        return Some(prog_data);
    }
    None
}

/// Returns the config path to write to (creating dirs if needed).
/// Prefers the existing file location; falls back to ProgramData.
pub(crate) fn config_path_for_write() -> PathBuf {
    if let Some(existing) = find_config() {
        return existing;
    }
    let dir = PathBuf::from(r"C:\ProgramData\mirage2tun");
    std::fs::create_dir_all(&dir).ok();
    dir.join("tun.json")
}

/// Persist `policy` into tun.json (read-modify-write).
/// Best-effort: logs a warning on failure, never returns an error.
pub(crate) fn save_policy_to_config(policy: &mirage_tun_core::policy::PolicyConfigRequest) {
    let path = config_path_for_write();

    // Read current JSON object (or start with empty object).
    let mut obj: serde_json::Map<String, serde_json::Value> = path
        .exists()
        .then(|| std::fs::read_to_string(&path).ok())
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Update only the policy field.
    match serde_json::to_value(policy) {
        Ok(v) => { obj.insert("policy".to_owned(), v); }
        Err(e) => {
            tracing::warn!("save_policy_to_config: serialize failed: {e}");
            return;
        }
    }

    match serde_json::to_string_pretty(&serde_json::Value::Object(obj)) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("save_policy_to_config: write failed: {e}");
            } else {
                tracing::info!("Policy persisted to {}", path.display());
            }
        }
        Err(e) => tracing::warn!("save_policy_to_config: to_string failed: {e}"),
    }
}

/// Persist `chains` into tun.json (read-modify-write).
/// Best-effort: logs a warning on failure, never returns an error.
pub(crate) fn save_chains_to_config(chains: &[crate::chains::ChainConfig]) {
    let path = config_path_for_write();

    let mut obj: serde_json::Map<String, serde_json::Value> = path
        .exists()
        .then(|| std::fs::read_to_string(&path).ok())
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    match serde_json::to_value(chains) {
        Ok(v) => { obj.insert("chains".to_owned(), v); }
        Err(e) => {
            tracing::warn!("save_chains_to_config: serialize failed: {e}");
            return;
        }
    }

    match serde_json::to_string_pretty(&serde_json::Value::Object(obj)) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("save_chains_to_config: write failed: {e}");
            } else {
                tracing::info!("Chains persisted to {}", path.display());
            }
        }
        Err(e) => tracing::warn!("save_chains_to_config: to_string failed: {e}"),
    }
}

async fn autostart_activate(
    state: Arc<crate::api::AppState>,
    params: crate::api::TunStartParams,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::api::activate_tun_inner(&state, params).await?;

    let s = state.service.lock().await;
    if let Some(socks5) = s.socks5_addr {
        let if_index = s.if_index;
        let dns_upstream = s.dns_upstream;
        drop(s);
        crate::ipstack::dns_warmup(socks5, if_index, dns_upstream).await;
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
        .with_env_filter("info,mirage2tun::ipstack=debug,mirage_tcpip_stack=debug")
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
    // Load config from tun.json if present, otherwise use defaults.
    let tun_cfg = Arc::new(
        find_config()
            .map(|p| TunConfig::load_from_tun_json(&p))
            .unwrap_or_default()
    );

    let tun_name = tun_cfg.tun_name.clone();
    let tun_addr = tun_cfg.tun_addr.clone();
    let api_bind = tun_cfg.api_bind;

    // ── Memory guard ──────────────────────────────────────────────────────────
    // TUN runs as a Windows service; on fatal pressure exit(0) so the SCM /
    // d-watchdog restarts the service cleanly.
    let _memory_guard = crate::runtime_guard::MemoryGuard::spawn(
        crate::runtime_guard::MemoryGuardConfig::default(),
        Box::new(|| {
            tracing::warn!("mirage2tun memory guard: fatal threshold — exiting for respawn");
            std::process::exit(0);
        }),
    );

    // Stale state cleanup
    cleanup_stale_routes(&tun_name).await;
    crate::proxy::clear_system_proxy().await;

    let wintun = match WintunHandle::create(&tun_name, &tun_addr, tun_cfg.tun_addr_v6.as_deref(), TUN_MTU, Some(&tun_cfg.tunnel_type)).await {
        Ok(w) => {
            info!("Wintun adapter '{tun_name}' ready");
            Some(w)
        }
        Err(e) => {
            tracing::error!("Failed to create Wintun adapter: {e}");
            None
        }
    };

    let policy = Arc::new(mirage_tun_core::policy::PolicyEngine::mirage_only());
    let dns_map = Arc::new(crate::dns_map::DnsMap::new());
    let chains = Arc::new(crate::chains::ChainRegistry::empty());
    let metrics = Arc::new(MetricsRegistry::new());
    let connections = Arc::new(crate::metrics::ConnectionRegistry::new());
    crate::metrics::spawn_gc(Arc::clone(&connections));

    let mut svc_state = ServiceState::new(tun_name.clone());
    svc_state.wintun = wintun;
    svc_state.dns_map = Arc::clone(&dns_map);
    svc_state.chains = Arc::clone(&chains);
    svc_state.drain_timeout_secs = tun_cfg.drain_timeout_secs;
    svc_state.dns_upstream = tun_cfg.dns_upstream;
    let svc_state = Arc::new(Mutex::new(svc_state));

    let app_state = Arc::new(AppState {
        service: Arc::clone(&svc_state),
        stop_tx,
        policy,
        dns_map,
        chains,
        metrics,
        connections,
        config: Arc::clone(&tun_cfg),
    });

    // Spawn MonitorLink if monitor_url is configured.
    if let Some(monitor_url) = tun_cfg.monitor_url.clone() {
        info!("MonitorLink: connecting to monitor at {monitor_url}");
        let (link, chain_rx) = crate::monitor_link::MonitorLink::new(
            monitor_url,
            tun_cfg.monitor_api_key.clone(),
        );
        // Subscribe to peer LM hosts BEFORE spawning so we don't miss the
        // first push (`watch::Sender::send` only stores the latest value;
        // late subscribers see it on the first `changed().await`).
        let peer_lm_rx = link.subscribe_peer_lm_hosts();
        link.spawn();
        crate::monitor_link::spawn_chain_watcher(chain_rx, Arc::clone(&app_state.chains));
        crate::monitor_link::spawn_peer_lm_bypass_watcher(peer_lm_rx, Arc::clone(&svc_state));
    }

    let router = crate::api::build_router(Arc::clone(&app_state));
    let listener = tokio::net::TcpListener::bind(api_bind).await?;
    info!("Management API listening on {api_bind}");

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
            crate::proxy::clear_system_proxy().await;
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
