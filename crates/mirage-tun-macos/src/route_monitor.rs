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
    capture_default: bool,
) {
    // Split mode has no 0/1 override. Watching for it would reinstall the
    // full-capture routes and then exit after five "drift" ticks.
    if !capture_default {
        return;
    }
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
    // STRUCTURAL check: confirm the `0/1` override route exists with Netif == our
    // utun, by reading the routing TABLE directly (`netstat -rn -f inet`).
    //
    // We must NOT probe a concrete address with `route get <ip>` — every relay
    // node IP gets a more-specific bypass HOST route via the real NIC, and so can
    // the configured `dns_upstream` (e.g. a stale `8.8.8.8 → en0 UGHS`). Probing
    // any such IP returns en0 and reports a FALSE drift on every tick, which after
    // 5 ticks `process::exit`s a perfectly healthy tunnel (the bug that capped
    // every Mac tun run at ~50s — confirmed 2026-05-31: `route get 8.8.8.8` = en0
    // while `route get 1.1.1.1` = utun5 and `0/1 → 10.255.0.1 utun5` was installed).
    //
    // Checking the `0/1` route's Netif is immune to per-host bypass routes: it asks
    // "is my default-via-tun override still installed?" — exactly what self-heal
    // needs — rather than "does this one address resolve to the tun?".
    let out = tokio::process::Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // macOS columns: Destination Gateway Flags Netif [Expire].
        // The 0.0.0.0/1 override is abbreviated "0/1" by netstat.
        let mut cols = line.split_whitespace();
        let dest = cols.next().unwrap_or("");
        if dest == "0/1" || dest == "0.0.0.0/1" {
            // Netif is the 4th column (index 3): skip Gateway + Flags.
            let netif = cols.nth(2).unwrap_or("");
            return Ok(netif == expected_iface);
        }
    }

    // No 0/1 route at all → the override is genuinely gone → real drift.
    Ok(false)
}
