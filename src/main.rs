mod api;
mod error;
mod firewall;
mod ipstack;
mod proxy;
mod routing;
mod service;
mod state;
mod wintun;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mirage2tun", version, about = "Mirage TUN adapter lifecycle service")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register and start the Windows Service (requires admin)
    Install,
    /// Stop and remove the Windows Service (requires admin)
    Uninstall,
    /// Dispatch to the Windows Service dispatcher (called by SCM)
    Run,
    /// Run service logic in foreground for debugging
    DebugRun,
    /// Copy current exe to mirage2tun-running.exe (apply update without reinstall)
    Update,
    /// Minimal Wintun read test — no IpStack, no tokio, just raw recv in a loop
    TestRead,
    /// End-to-end TUN test: start service, activate TUN, verify exit IP + DNS, stop (requires admin + mirage2web running)
    Evaluate,
    /// Diagnose: start TUN, send traffic, collect probe reports from L1+L2, show where packets drop (requires admin + mirage2web running)
    Diagnose {
        /// Path to client-config.json (reads management_key)
        #[arg(long)]
        config: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Install => {
            if let Err(e) = install_service() {
                eprintln!("Install failed: {e}");
                std::process::exit(1);
            }
        }
        Cmd::Uninstall => {
            if let Err(e) = uninstall_service() {
                eprintln!("Uninstall failed: {e}");
                std::process::exit(1);
            }
        }
        Cmd::Run => {
            if let Err(e) = service::dispatch() {
                eprintln!("Service dispatch failed: {e}");
                std::process::exit(1);
            }
        }
        Cmd::DebugRun => {
            debug_run();
        }
        Cmd::Update => {
            if let Err(e) = update_running_exe() {
                eprintln!("Update failed: {e}");
                std::process::exit(1);
            }
        }
        Cmd::TestRead => {
            test_read();
        }
        Cmd::Evaluate => {
            evaluate();
        }
        Cmd::Diagnose { config } => {
            diagnose(&config);
        }
    }
}

fn test_read() {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::Foundation::HANDLE;

    println!("=== Wintun raw read test ===");

    // Load wintun.dll
    let lib = unsafe { libloading::Library::new("wintun.dll") }.expect("load wintun.dll");

    type FnOpen = unsafe extern "C" fn(*const u16) -> *mut std::ffi::c_void;
    type FnStart = unsafe extern "C" fn(*mut std::ffi::c_void, u32) -> *mut std::ffi::c_void;
    type FnRecv = unsafe extern "C" fn(*mut std::ffi::c_void, *mut u32) -> *mut u8;
    type FnRelease = unsafe extern "C" fn(*mut std::ffi::c_void, *mut u8);
    type FnGetEvent = unsafe extern "C" fn(*mut std::ffi::c_void) -> HANDLE;
    type FnEndSession = unsafe extern "C" fn(*mut std::ffi::c_void);
    type FnClose = unsafe extern "C" fn(*mut std::ffi::c_void);

    type FnCreate = unsafe extern "C" fn(*const u16, *const u16, *const std::ffi::c_void) -> *mut std::ffi::c_void;
    let fn_open: libloading::Symbol<FnOpen> = unsafe { lib.get(b"WintunOpenAdapter\0") }.expect("WintunOpenAdapter");
    let fn_create: libloading::Symbol<FnCreate> = unsafe { lib.get(b"WintunCreateAdapter\0") }.expect("WintunCreateAdapter");
    let fn_start: libloading::Symbol<FnStart> = unsafe { lib.get(b"WintunStartSession\0") }.expect("WintunStartSession");
    let fn_recv: libloading::Symbol<FnRecv> = unsafe { lib.get(b"WintunReceivePacket\0") }.expect("WintunReceivePacket");
    let fn_release: libloading::Symbol<FnRelease> = unsafe { lib.get(b"WintunReleaseReceivePacket\0") }.expect("WintunReleaseReceivePacket");
    let fn_get_event: libloading::Symbol<FnGetEvent> = unsafe { lib.get(b"WintunGetReadWaitEvent\0") }.expect("WintunGetReadWaitEvent");
    let fn_end: libloading::Symbol<FnEndSession> = unsafe { lib.get(b"WintunEndSession\0") }.expect("WintunEndSession");
    let fn_close: libloading::Symbol<FnClose> = unsafe { lib.get(b"WintunCloseAdapter\0") }.expect("WintunCloseAdapter");

    let name: Vec<u16> = std::ffi::OsStr::new("mirage0")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let tunnel_type: Vec<u16> = std::ffi::OsStr::new("Mirage")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut adapter = unsafe { fn_open(name.as_ptr()) };
    if adapter.is_null() {
        println!("Open failed, creating adapter...");
        adapter = unsafe { fn_create(name.as_ptr(), tunnel_type.as_ptr(), std::ptr::null()) };
        if adapter.is_null() {
            println!("ERROR: WintunCreateAdapter also failed");
            return;
        }
    }
    println!("Adapter ready: {:?}", adapter);

    // Assign IP
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ip", "set", "address", "mirage0", "static", "10.0.85.1", "255.255.255.0"])
        .output();
    println!("IP assigned 10.0.85.1/24");
    std::thread::sleep(std::time::Duration::from_secs(2));

    let session = unsafe { fn_start(adapter, 0x0020_0000) };
    if session.is_null() {
        println!("ERROR: WintunStartSession returned NULL");
        unsafe { fn_close(adapter) };
        return;
    }
    println!("Session started: {:?}", session);

    let event: HANDLE = unsafe { fn_get_event(session) };
    println!("Event handle: 0x{:x}", event as usize);

    // Add route so traffic hits mirage0
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "set", "interface", "mirage0", "metric=1"])
        .output();
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ipv4", "add", "route", "198.51.100.0/24", "interface=mirage0", "metric=1", "store=active"])
        .output();
    println!("Test route 198.51.100.0/24 added to mirage0");

    println!("Waiting for packets (5s timeout per iteration, 10 iterations)...");
    println!("Try: ping 198.51.100.1 from another terminal");
    for i in 0..10 {
        let wait = unsafe { WaitForSingleObject(event, 5000) };
        print!("[{i}] Wait={wait} ");

        let mut pkt_size: u32 = 0;
        let pkt = unsafe { fn_recv(session, &mut pkt_size) };
        if pkt.is_null() {
            println!("(no packet)");
        } else {
            let data = unsafe { std::slice::from_raw_parts(pkt, pkt_size as usize) };
            let ver = data.first().map(|b| b >> 4).unwrap_or(0);
            let proto = if ver == 4 && data.len() >= 10 { data[9] } else { 0 };
            println!("GOT {} bytes IPv{ver} proto={proto}", pkt_size);
            unsafe { fn_release(session, pkt) };
        }
    }

    println!("Closing session...");
    unsafe { fn_end(session) };
    unsafe { fn_close(adapter) };
    println!("Done.");
}

use std::os::windows::ffi::OsStrExt;

/// Compute the `-running.exe` path next to the given exe.
fn running_exe_path(exe: &std::path::Path) -> std::path::PathBuf {
    let parent = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    let ext = exe.extension().unwrap_or_default();
    let mut running = parent.join("mirage2tun-running");
    running.set_extension(ext);
    running
}

fn update_running_exe() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let running_exe = running_exe_path(&exe);
    std::fs::copy(&exe, &running_exe)?;
    println!("Copied {} -> {}", exe.display(), running_exe.display());
    println!("Updated. Restart service to apply.");
    Ok(())
}

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let exe = std::env::current_exe()?;
    let parent = exe.parent().unwrap_or_else(|| std::path::Path::new("."));

    // Copy wintun.dll to same dir if needed
    let src_dll = parent.join("wintun.dll");
    if !src_dll.exists() {
        return Err(format!("wintun.dll not found at {}", src_dll.display()).into());
    }

    // Compute running exe path and copy current exe there
    let running_exe = running_exe_path(&exe);
    std::fs::copy(&exe, &running_exe)?;
    println!("Copied {} -> {}", exe.display(), running_exe.display());

    // Ensure wintun.dll is next to running exe (same dir, so already there)
    // running_exe is in same parent as exe, so wintun.dll is already alongside it.

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )?;

    let service_info = ServiceInfo {
        name: OsString::from("mirage2tun"),
        display_name: OsString::from("Mirage TUN Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: running_exe.clone(),
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description("Mirage TUN adapter lifecycle manager")?;

    // Set SCM recovery policy: restart on failure
    let recovery = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(1),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: std::time::Duration::from_secs(30),
            },
        ]),
    };
    service.update_failure_actions(recovery)?;
    println!("SCM recovery policy set (restart after 1s/5s/30s).");

    println!(
        "Service registered with executable: {}",
        running_exe.display()
    );
    println!("Starting...");
    service.start(&[OsString::from("run")])?;
    println!("Service started.");
    Ok(())
}

fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )?;

    let service = manager.open_service(
        "mirage2tun",
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    let _ = service.stop();

    // Wait for stop
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let status = service.query_status()?;
        if status.current_state == windows_service::service::ServiceState::Stopped {
            break;
        }
    }

    service.delete()?;
    println!("Service uninstalled.");
    Ok(())
}

fn debug_run() {
    let file_appender = tracing_appender::rolling::daily(
        "C:\\ProgramData\\mirage2tun\\logs",
        "mirage2tun.log",
    );
    let (_non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,mirage2tun::ipstack=debug,netstack_smoltcp=debug")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed: system resources exhausted");

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());

    rt.block_on(async move {
        tokio::select! {
            result = service::run_service_logic(None, stop_tx.clone(), stop_rx) => {
                if let Err(e) = result {
                    tracing::error!("debug-run error: {e}");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl-C received, shutting down");
                let _ = stop_tx.send(());
            }
        }
    });
}

fn evaluate() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
        let stop_tx2 = stop_tx.clone();

        // Spawn service logic in background
        let svc_handle = tokio::spawn(async move {
            if let Err(e) = service::run_service_logic(None, stop_tx2, stop_rx).await {
                eprintln!("[evaluate] service error: {e}");
            }
        });

        let api = "http://127.0.0.1:19485";
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .no_proxy()
            .build()
            .expect("reqwest client");

        // 1) Wait for API ready
        print!("[1/5] Waiting for API...");
        let api_ok = poll_health(&client, api).await;
        println!(" {}", verdict(api_ok));
        if !api_ok {
            eprintln!("ABORT: API never became ready");
            let _ = stop_tx.send(());
            let _ = svc_handle.await;
            std::process::exit(1);
        }

        // 2) Activate TUN
        print!("[2/5] POST /tun/start...");
        let start_ok = activate_tun(&client, api).await;
        println!(" {}", verdict(start_ok));
        if !start_ok {
            eprintln!("ABORT: TUN activation failed");
            let _ = stop_tx.send(());
            let _ = svc_handle.await;
            std::process::exit(1);
        }

        // Let routes + DNS settle
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // 3) Check exit IP
        print!("[3/5] Checking exit IP (ifconfig.me)...");
        let (ip_ok, exit_ip) = check_exit_ip().await;
        if ip_ok {
            println!(" PASS ({})", exit_ip);
        } else {
            println!(" FAIL (got: {})", exit_ip);
        }

        // 4) Check DNS
        print!("[4/5] Checking DNS (example.com)...");
        let dns_ok = check_dns().await;
        println!(" {}", verdict(dns_ok));

        // 5) Stop TUN
        print!("[5/5] POST /tun/stop...");
        let stop_ok = deactivate_tun(&client, api).await;
        println!(" {}", verdict(stop_ok));

        // Shutdown service
        let _ = stop_tx.send(());
        let _ = svc_handle.await;

        // Final verdict
        println!();
        let all_pass = api_ok && start_ok && ip_ok && dns_ok && stop_ok;
        if all_pass {
            println!("=== ALL PASS ===");
        } else {
            println!("=== FAIL ===");
            std::process::exit(1);
        }
    });
}

fn verdict(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

async fn poll_health(client: &reqwest::Client, api: &str) -> bool {
    for _ in 0..20 {
        match client.get(format!("{api}/health")).send().await {
            Ok(r) if r.status().is_success() => return true,
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

async fn activate_tun(client: &reqwest::Client, api: &str) -> bool {
    let body = serde_json::json!({
        "socks5_addr": "127.0.0.1:19480",
        "relay_addrs": ["91.218.245.247", "45.59.119.139"]
    });
    match client.post(format!("{api}/tun/start")).json(&body).send().await {
        Ok(r) => r.status().is_success(),
        Err(e) => {
            eprintln!(" error: {e}");
            false
        }
    }
}

async fn check_exit_ip() -> (bool, String) {
    // Route through SOCKS5 proxy (mirage2web) → relay chain → exit node
    // Direct requests get blocked by WFP kill-switch
    let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:19480").expect("proxy url");
    let tun_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .proxy(proxy)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    match tun_client.get("http://ifconfig.me/ip").send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default().trim().to_string();
            let ok = body.contains("45.59.119.139");
            (ok, body)
        }
        Err(e) => (false, format!("error: {e}")),
    }
}

async fn check_dns() -> bool {
    // Route through SOCKS5 to verify DNS works end-to-end via relay
    let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:19480").expect("proxy url");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .proxy(proxy)
        .build();
    match client {
        Ok(c) => c.get("http://example.com").send().await.is_ok(),
        Err(_) => false,
    }
}

async fn deactivate_tun(client: &reqwest::Client, api: &str) -> bool {
    match client.post(format!("{api}/tun/stop")).send().await {
        Ok(r) => r.status().is_success(),
        Err(e) => {
            eprintln!(" error: {e}");
            false
        }
    }
}

fn diagnose(config_path: &str) {
    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed: system resources exhausted");

    rt.block_on(async move {
        run_diagnose(config_path).await;
    });
}

/// Extract port number from an addr string like "91.218.245.247:4702" → 4702.
fn port_from_addr(addr: &str) -> Option<u16> {
    addr.rsplit(':').next().and_then(|p| p.parse().ok())
}

/// Read chain ports (l1_port, l2_port) for the given chain_id from config.
/// If chain_id is empty, falls back to the first chain.
fn read_chain_ports(config_path: &str, chain_id: &str) -> (Option<u16>, Option<u16>) {
    let data = match std::fs::read_to_string(config_path) {
        Ok(d) => d,
        Err(_) => return (None, None),
    };
    let v: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };

    let chains = match v.get("chains").and_then(|c| c.as_array()) {
        Some(arr) => arr,
        None => return (None, None),
    };

    // Find matching chain by chain_id, fall back to first.
    let chain = chains
        .iter()
        .find(|c| {
            c.get("chain_id")
                .and_then(|x| x.as_str())
                .map(|id| id == chain_id)
                .unwrap_or(false)
        })
        .or_else(|| chains.first());

    let chain = match chain {
        Some(c) => c,
        None => return (None, None),
    };

    let l1_port = chain
        .get("l1")
        .and_then(|l| l.get("addr"))
        .and_then(|a| a.as_str())
        .and_then(port_from_addr);

    let l2_port = chain
        .get("l2")
        .and_then(|l| l.get("addr"))
        .and_then(|a| a.as_str())
        .and_then(port_from_addr);

    (l1_port, l2_port)
}

async fn run_diagnose(config_path: &str) {
    println!("=== mirage2tun diagnose ===");
    println!();

    let management_key = read_management_key(config_path);

    let api = "http://127.0.0.1:19485";

    // Direct client — no proxy
    let direct = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()
        .expect("direct reqwest client");

    // ── Step 1: mirage2tun API health ────────────────────────────────────────
    print!("[1/6] Waiting for mirage2tun API (127.0.0.1:19485)...");
    let api_ok = poll_health(&direct, api).await;
    println!(" {}", verdict(api_ok));
    if !api_ok {
        eprintln!("ABORT: mirage2tun API not reachable");
        std::process::exit(1);
    }

    // ── Step 2: mirage2web health ─────────────────────────────────────────────
    print!("[2/6] GET http://127.0.0.1:4498/admin/health ...");
    let health_ok = match direct.get("http://127.0.0.1:4498/admin/health").send().await {
        Ok(r) if r.status().is_success() => {
            println!(" PASS");
            true
        }
        Ok(r) => {
            println!(" FAIL (HTTP {})", r.status());
            false
        }
        Err(e) => {
            println!(" FAIL: {e}");
            false
        }
    };

    // ── Step 3: mirage2web status → active_chain_id → resolve ports ──────────
    let mut active_chain_id = String::new();
    let mut pool_size: u64 = 0;
    let mut pool_idle: u64 = 0;
    let mut pool_leased: u64 = 0;
    let mut pool_reconnecting: u64 = 0;

    print!("[3/6] GET http://127.0.0.1:4498/admin/status ...");
    if let Some(ref key) = management_key {
        match direct
            .get("http://127.0.0.1:4498/admin/status")
            .header("Authorization", format!("Bearer {key}"))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                match r.json::<serde_json::Value>().await {
                    Ok(v) => {
                        if let Some(chain) = v.get("active_chain_id").and_then(|x| x.as_str()) {
                            active_chain_id = chain.to_string();
                        }
                        if let Some(n) = v.get("pool_size").and_then(|x| x.as_u64()) {
                            pool_size = n;
                        }
                        if let Some(n) = v.get("pool_idle").and_then(|x| x.as_u64()) {
                            pool_idle = n;
                        }
                        if let Some(n) = v.get("pool_leased").and_then(|x| x.as_u64()) {
                            pool_leased = n;
                        }
                        if let Some(n) = v.get("pool_reconnecting").and_then(|x| x.as_u64()) {
                            pool_reconnecting = n;
                        }
                        println!(" PASS");
                        println!("  active_chain_id:  {active_chain_id}");
                        println!("  pool_size:        {pool_size}");
                        println!("  pool_idle:        {pool_idle}");
                        println!("  pool_leased:      {pool_leased}");
                        println!("  pool_reconnecting:{pool_reconnecting}");
                    }
                    Err(e) => println!(" FAIL (parse): {e}"),
                }
            }
            Ok(r) => println!(" FAIL (HTTP {})", r.status()),
            Err(e) => println!(" FAIL: {e}"),
        }
    } else {
        println!(" SKIP (no management_key)");
    }

    // Resolve L1/L2 ports from config using the active chain id.
    let (l1_port, l2_port) = read_chain_ports(config_path, &active_chain_id);
    println!(
        "  [config] L1 port: {}  L2 port: {}  (chain: {})",
        l1_port.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
        l2_port.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
        if active_chain_id.is_empty() { "fallback-to-first" } else { &active_chain_id },
    );
    println!();

    // ── Step 4: 10 sequential SOCKS5 requests ────────────────────────────────
    println!("[4/6] Sending 10 requests via socks5h://127.0.0.1:19480 -> http://ifconfig.me/ip");
    let socks_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:19480").expect("socks5 proxy url"))
        .build()
        .expect("socks5 reqwest client");

    let mut pass_count = 0u32;
    let mut fail_count = 0u32;
    for i in 1u32..=10 {
        let start = std::time::Instant::now();
        match socks_client.get("http://ifconfig.me/ip").send().await {
            Ok(r) => {
                let elapsed = start.elapsed().as_secs_f64();
                match r.text().await {
                    Ok(body) => {
                        let ip = body.trim().to_string();
                        println!("  [{i}/10] OK {ip} ({:.1}s)", elapsed);
                        pass_count += 1;
                    }
                    Err(e) => {
                        println!("  [{i}/10] FAIL: body read error: {e}");
                        fail_count += 1;
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                let label = if msg.contains("timed out") || msg.contains("timeout") {
                    "timeout"
                } else if msg.contains("refused") {
                    "connection refused"
                } else {
                    &msg
                };
                println!("  [{i}/10] FAIL: {label}");
                fail_count += 1;
            }
        }
    }

    // ── Step 5: L1 probe report ──────────────────────────────────────────────
    println!();
    let l1_port_val = l1_port.unwrap_or(4702);
    println!("[5/6] GET http://91.218.245.247:19411/report (filter port {l1_port_val})");
    let (l1_conns, l1_rtt, l1_retrans) = fetch_probe_report(
        &direct,
        "http://91.218.245.247:19411/report",
        "m2m-probe-l1-secret-2026",
        l1_port_val,
    )
    .await;

    // ── Step 6: L2 probe report ──────────────────────────────────────────────
    let l2_port_val = l2_port.unwrap_or(4700);
    println!("[6/6] GET http://45.59.119.139:19411/report (filter port {l2_port_val})");
    let (l2_conns, l2_rtt, l2_retrans) = fetch_probe_report(
        &direct,
        "http://45.59.119.139:19411/report",
        "m2m-probe-l2-test-2026",
        l2_port_val,
    )
    .await;

    // ── Summary ───────────────────────────────────────────────────────────────
    let total = pass_count + fail_count;
    let loss_pct = if total > 0 {
        (fail_count as f64 / total as f64 * 100.0) as u32
    } else {
        0
    };

    println!();
    println!("=== SUMMARY ===");
    println!("mirage2tun API:    {}", verdict(api_ok));
    println!("mirage2web health: {}", verdict(health_ok));
    println!("Active chain:      {}", if active_chain_id.is_empty() { "unknown" } else { &active_chain_id });
    println!(
        "Pool: size={pool_size} idle={pool_idle} leased={pool_leased} reconnecting={pool_reconnecting}"
    );
    println!("Requests:          {pass_count}/{total} passed ({loss_pct}% loss)");
    println!("L1 :{l1_port_val}: {l1_conns} conns | RTT avg {l1_rtt}ms | retrans {l1_retrans}");
    println!("L2 :{l2_port_val}: {l2_conns} conns | RTT avg {l2_rtt}ms | retrans {l2_retrans}");
}

fn read_management_key(config_path: &str) -> Option<String> {
    let data = std::fs::read_to_string(config_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    v.get("management_key")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

/// Fetch probe report JSON, filter connections by ESTABLISHED state + `local_port`,
/// return (count, avg_rtt_ms, total_retrans). Also prints up to 5 individual connections.
async fn fetch_probe_report(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    port: u16,
) -> (usize, u64, u64) {
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
            Ok(v) => parse_probe_report(&v, port),
            Err(e) => {
                println!("  FAIL (parse): {e}");
                (0, 0, 0)
            }
        },
        Ok(r) => {
            println!("  FAIL (HTTP {})", r.status());
            (0, 0, 0)
        }
        Err(e) => {
            println!("  FAIL: {e}");
            (0, 0, 0)
        }
    }
}

fn parse_probe_report(v: &serde_json::Value, port: u16) -> (usize, u64, u64) {
    let conns = match v.get("connections").and_then(|c| c.as_array()) {
        Some(arr) => arr,
        None => return (0, 0, 0),
    };

    // ── ALL established connections summary ───────────────────────────────────
    let all_established: Vec<&serde_json::Value> = conns
        .iter()
        .filter(|c| {
            c.get("state")
                .and_then(|x| x.as_str())
                .map(|s| s == "ESTABLISHED")
                .unwrap_or(false)
        })
        .collect();

    println!("  Total ESTABLISHED: {}", all_established.len());

    // Group by local_port
    let mut by_port: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for c in &all_established {
        let lp = c
            .get("local_port")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        *by_port.entry(lp).or_insert(0) += 1;
    }
    if !by_port.is_empty() {
        let mut entries: Vec<(u64, usize)> = by_port.into_iter().collect();
        entries.sort_by_key(|(p, _)| *p);
        let summary = entries
            .iter()
            .map(|(p, n)| format!(":{p} ({n})"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  By port: {summary}");
    }

    // ── Filtered: ESTABLISHED + matching local_port ───────────────────────────
    let filtered: Vec<&serde_json::Value> = all_established
        .iter()
        .copied()
        .filter(|c| {
            c.get("local_port")
                .and_then(|x| x.as_u64())
                .map(|p| p == port as u64)
                .unwrap_or(false)
        })
        .collect();

    let count = filtered.len();
    if count == 0 {
        println!("  Filtered to :{port}: 0 conns");
        return (0, 0, 0);
    }

    let total_rtt: f64 = filtered
        .iter()
        .filter_map(|c| {
            c.get("metrics")
                .and_then(|m| m.get("rtt_ms"))
                .and_then(|x| x.as_f64())
        })
        .sum();
    let rtt_samples = filtered
        .iter()
        .filter(|c| {
            c.get("metrics")
                .and_then(|m| m.get("rtt_ms"))
                .and_then(|x| x.as_f64())
                .is_some()
        })
        .count();
    let avg_rtt = if rtt_samples > 0 {
        total_rtt / rtt_samples as f64
    } else {
        0.0
    };

    let total_retrans: u64 = filtered
        .iter()
        .filter_map(|c| {
            c.get("metrics")
                .and_then(|m| m.get("retransmits"))
                .and_then(|x| x.as_u64())
        })
        .sum();

    println!(
        "  Filtered to :{port}: {count} conns | RTT avg {avg_rtt:.1}ms | retrans {total_retrans}"
    );

    // Print up to 5 individual connections
    for (idx, c) in filtered.iter().take(5).enumerate() {
        let remote = c
            .get("remote_addr")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let rtt = c
            .get("metrics")
            .and_then(|m| m.get("rtt_ms"))
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0);
        let retrans = c
            .get("metrics")
            .and_then(|m| m.get("retransmits"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let bytes_rx = c
            .get("metrics")
            .and_then(|m| m.get("bytes_received"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let bytes_tx = c
            .get("metrics")
            .and_then(|m| m.get("bytes_sent"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        println!(
            "    [{idx}] {remote} RTT={rtt:.1}ms retrans={retrans} rx={bytes_rx}B tx={bytes_tx}B"
        );
    }

    (count, avg_rtt as u64, total_retrans)
}
