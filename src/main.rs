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
    }
}

fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let exe = std::env::current_exe()?;

    // Check wintun.dll
    let dll_path = exe.parent().unwrap().join("wintun.dll");
    if !dll_path.exists() {
        return Err(format!("wintun.dll not found at {}", dll_path.display()).into());
    }

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
        executable_path: exe,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description("Mirage TUN adapter lifecycle manager")?;

    println!("Service installed. Starting...");
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
            result = service::run_service_logic((), stop_rx) => {
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
