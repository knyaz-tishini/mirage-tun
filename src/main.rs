mod api;
mod error;
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
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
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
