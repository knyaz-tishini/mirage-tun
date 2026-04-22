use tokio::process::Command;
use tracing::{info, warn};

const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Enable the Windows system proxy and point it at `proxy_server`.
///
/// `proxy_server` format:
/// - HTTP CONNECT: `"127.0.0.1:19481"`
/// - SOCKS5:       `"socks=127.0.0.1:19480"`
pub async fn set_system_proxy(proxy_server: &str) {
    // 1. WinINET — registry (browsers)
    let enable_ok = Command::new("reg")
        .args([
            "add", REG_KEY,
            "/v", "ProxyEnable",
            "/t", "REG_DWORD",
            "/d", "1",
            "/f",
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let server_ok = Command::new("reg")
        .args([
            "add", REG_KEY,
            "/v", "ProxyServer",
            "/t", "REG_SZ",
            "/d", proxy_server,
            "/f",
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if enable_ok && server_ok {
        info!("WinINET proxy set to {proxy_server}");
    } else {
        warn!("WinINET proxy set failed (enable={enable_ok}, server={server_ok})");
    }

    // 2. WinHTTP — netsh (curl, PowerShell, system services).
    // WinHTTP does not support SOCKS via netsh — skip for socks= addresses.
    if !proxy_server.starts_with("socks") {
        let ok = Command::new("netsh")
            .args(["winhttp", "set", "proxy", proxy_server])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            info!("WinHTTP proxy set to {proxy_server}");
        } else {
            warn!("WinHTTP proxy set failed for {proxy_server}");
        }
    }

    // 3. Notify running apps of settings change.
    notify_proxy_change().await;
}

/// Disable the Windows system proxy.
pub async fn clear_system_proxy() {
    // 1. WinINET — disable via registry
    let ok = Command::new("reg")
        .args([
            "add", REG_KEY,
            "/v", "ProxyEnable",
            "/t", "REG_DWORD",
            "/d", "0",
            "/f",
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ok {
        info!("WinINET proxy cleared");
    } else {
        warn!("WinINET proxy clear failed");
    }

    // 2. WinHTTP — reset to direct
    let ok = Command::new("netsh")
        .args(["winhttp", "reset", "proxy"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ok {
        info!("WinHTTP proxy reset to direct");
    } else {
        warn!("WinHTTP proxy reset failed");
    }

    // 3. Notify running apps.
    notify_proxy_change().await;
}

/// Notify running WinINET applications (browsers, etc.) that proxy settings
/// changed. Calls `InternetSetOption` with:
/// - option 39 = `INTERNET_OPTION_SETTINGS_CHANGED`
/// - option 37 = `INTERNET_OPTION_REFRESH`
async fn notify_proxy_change() {
    let ps_cmd = concat!(
        "Add-Type -TypeDefinition '",
        "using System.Runtime.InteropServices; ",
        "public class WinInet { ",
        "[DllImport(\"wininet.dll\", SetLastError=true)] ",
        "public static extern bool InternetSetOption(",
        "System.IntPtr hInternet, int dwOption, System.IntPtr lpBuffer, int dwBufferLength); ",
        "}'; ",
        "[WinInet]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0); ",
        "[WinInet]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0)"
    );

    let ok = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !ok {
        warn!("InternetSetOption notification failed");
    }
}
