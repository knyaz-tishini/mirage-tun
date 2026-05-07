use crate::routing::MacosRouting;
use mirage_tun_core::traits::PlatformRouting;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

pub fn spawn_route_monitor(
    tun_name: String,
    routing: Arc<Mutex<MacosRouting>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut fail_count: u32 = 0;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {}
            }

            match check_default_route(&tun_name).await {
                Ok(true) => {
                    fail_count = 0;
                }
                Ok(false) => {
                    fail_count += 1;
                    warn!(
                        tun = %tun_name,
                        fail_count,
                        "route-monitor: default route drifted — re-applying"
                    );
                    let mut guard = routing.lock().await;
                    if let Err(e) = guard.set_default_route(&tun_name).await {
                        error!(tun = %tun_name, err = %e, "route-monitor: re-apply failed");
                    }
                    if fail_count >= 5 {
                        error!(
                            tun = %tun_name,
                            "route-monitor: 5 consecutive failures — exiting for respawn"
                        );
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    fail_count += 1;
                    error!(
                        tun = %tun_name,
                        err = %e,
                        fail_count,
                        "route-monitor: route check error"
                    );
                    if fail_count >= 5 {
                        error!(
                            tun = %tun_name,
                            "route-monitor: 5 consecutive errors — exiting for respawn"
                        );
                        std::process::exit(1);
                    }
                }
            }
        }
    });
}

async fn check_default_route(expected_iface: &str) -> Result<bool, String> {
    // Probe with a public IP that falls under our 0.0.0.0/1 override.
    // `route get 0.0.0.0` always resolves to the system /0 default and would
    // give a false-positive drift on every tick.  8.8.8.8 picks the most
    // specific /1 route — must point at our utun.
    let out = tokio::process::Command::new("route")
        .args(["-n", "get", "8.8.8.8"])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(iface) = trimmed.strip_prefix("interface:") {
            return Ok(iface.trim() == expected_iface);
        }
    }

    Ok(false)
}
