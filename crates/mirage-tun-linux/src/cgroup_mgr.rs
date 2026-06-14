/// cgroup v2 directory lifecycle: create a dedicated leaf cgroup per isolated
/// process, move the PID into it, and remove it on teardown.
///
/// We create the cgroup directly under the unified hierarchy
/// (`/sys/fs/cgroup/mirage.slice/mirage-proc-<pid>.scope/`) rather than asking
/// systemd. Moving an *existing* PID via `systemd-run --scope` needs systemd
/// >= 250's `--pid=` flag plus a placeholder unit; a direct mkdir is portable
/// across systemd / non-systemd / container hosts and is sufficient for BPF
/// cgroup-attach, which needs no controller delegation (BPF programs attach to
/// the cgroup fd directly, independent of `cgroup.subtree_control`).
///
/// All functions are synchronous (blocking). Call from `tokio::task::spawn_blocking`.
use std::fs;
use std::io;

use tracing::debug;

use crate::error::LinuxTunError;

/// Parent slice holding all per-process Mirage scopes.
const MIRAGE_SLICE: &str = "/sys/fs/cgroup/mirage.slice";

/// Returns `true` if PID 1 is `systemd` (informational only — we use the direct
/// path regardless). Reads `/proc/1/comm`; non-panicking, `false` on I/O error.
pub(crate) fn is_systemd_host() -> bool {
    match fs::read_to_string("/proc/1/comm") {
        Ok(comm) => comm.trim() == "systemd",
        Err(_) => false,
    }
}

/// Create a dedicated leaf cgroup for `pid` and move it in. Returns the absolute
/// cgroup directory path (e.g. `/sys/fs/cgroup/mirage.slice/mirage-proc-42.scope`).
pub(crate) fn move_pid_to_cgroup(pid: u32) -> Result<String, LinuxTunError> {
    if is_systemd_host() {
        debug!(pid, "systemd host: creating Mirage cgroup directly (no systemd-run)");
    }

    // Ensure the parent slice exists.
    if let Err(e) = fs::create_dir(MIRAGE_SLICE) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(LinuxTunError::Cgroup(format!("create {MIRAGE_SLICE}: {e}")));
        }
    }

    // Create the per-PID leaf scope.
    let scope_dir = format!("{MIRAGE_SLICE}/mirage-proc-{pid}.scope");
    if let Err(e) = fs::create_dir(&scope_dir) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(LinuxTunError::Cgroup(format!("create {scope_dir}: {e}")));
        }
    }

    // Move the PID into the scope by writing to `cgroup.procs`.
    let procs_path = format!("{scope_dir}/cgroup.procs");
    fs::write(&procs_path, pid.to_string())
        .map_err(|e| LinuxTunError::Cgroup(format!("write pid to {procs_path}: {e}")))?;

    Ok(scope_dir)
}

/// Remove a cgroup directory. Any lingering PIDs are first moved back to the
/// root cgroup (best-effort) so the now-empty directory can be removed.
pub(crate) fn remove_cgroup(cgroup_path: &str) -> Result<(), LinuxTunError> {
    let procs_path = format!("{cgroup_path}/cgroup.procs");
    if let Ok(content) = fs::read_to_string(&procs_path) {
        for pid_str in content.split_whitespace() {
            let _ = fs::write("/sys/fs/cgroup/cgroup.procs", pid_str);
        }
    }

    fs::remove_dir(cgroup_path)
        .map_err(|e| LinuxTunError::Cgroup(format!("remove_dir {cgroup_path}: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `is_systemd_host()` returns a bool without panicking (any host/container).
    #[test]
    fn is_systemd_host_no_panic() {
        let _ = is_systemd_host();
    }
}
