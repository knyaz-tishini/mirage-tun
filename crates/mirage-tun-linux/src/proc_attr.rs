/// `/proc`-based flow attribution: `/proc/net/{tcp,udp}[6]` → socket inode → pid.
///
/// Used by `PlatformExecutor::attribute` to map an intercepted flow to the
/// originating process. The per-process enforcement (`enforce`) then moves that
/// pid into a dedicated cgroup itself, so attribution only needs pid + exe paths
/// (no cgroup lookup here). `cgroup_path_to_id` is exposed for the enforcement /
/// smoke paths, which create the dedicated cgroup and need its v2 id.
///
/// All functions are synchronous (blocking). Call from `tokio::task::spawn_blocking`.
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mirage_tun_core::plane::ProcessIdentity;
use mirage_tun_core::policy::ProcessInfo;
use mirage_tun_core::traits::FlowProto;

/// Attribute an intercepted flow to a `ProcessIdentity` (pid + exe + ancestors).
///
/// Steps:
///   1. Scan `/proc/net/{tcp,udp}[6]` for the socket matching `src_port` (and,
///      when possible, the remote `dst`) → socket inode.
///   2. Walk `/proc/*/fd/*` to find the PID owning that inode.
///   3. Read the exe path + ancestor exe paths.
pub(crate) fn attribute_flow(
    src_port: u16,
    dst: SocketAddr,
    proto: FlowProto,
) -> Option<ProcessIdentity> {
    let inode = find_inode_by_port(src_port, proto, dst)?;
    let pid = inode_to_pid(inode)?;
    let exe_path = read_exe_path(pid).unwrap_or_default();
    let ancestor_paths = read_ancestor_paths(pid, 3);
    Some(ProcessIdentity::from_process_info(ProcessInfo {
        pid,
        exe_path,
        ancestor_paths,
    }))
}

// ── /proc/net/{tcp,udp}[6] parsing ───────────────────────────────────────────

/// Find the socket inode for an outbound flow with local port `src_port`.
///
/// `/proc/net/tcp` format (space-separated, header on line 0):
///   sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
/// field[1] = local `HEXADDR:HEXPORT`, field[2] = rem, field[9] = inode.
/// Address is little-endian hex; port is big-endian hex.
///
/// Prefers an entry whose remote address matches `dst`, then falls back to a
/// local-port-only match (the ephemeral source port is unique per active
/// outbound connection, so the fallback is reliable in practice).
fn find_inode_by_port(src_port: u16, proto: FlowProto, dst: SocketAddr) -> Option<u64> {
    let is_ipv6 = matches!(dst, SocketAddr::V6(_));
    let path = match (proto, is_ipv6) {
        (FlowProto::Tcp, false) => "/proc/net/tcp",
        (FlowProto::Tcp, true) => "/proc/net/tcp6",
        (FlowProto::Udp, false) => "/proc/net/udp",
        (FlowProto::Udp, true) => "/proc/net/udp6",
    };

    let content = fs::read_to_string(path).ok()?;
    parse_proc_net_match(&content, src_port, Some(dst))
        .or_else(|| parse_proc_net_match(&content, src_port, None))
}

/// Parse a `/proc/net/{tcp,udp}[6]` table for a socket whose local port equals
/// `src_port`. When `want_rem` is `Some`, the remote address must also match.
/// Returns the socket inode.
pub(crate) fn parse_proc_net_match(
    content: &str,
    src_port: u16,
    want_rem: Option<SocketAddr>,
) -> Option<u64> {
    let port_hex = format!("{src_port:04X}");

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // field[1] = "local_address:port" — port is the hex chars after the last ':'.
        let Some((_, lport)) = fields[1].rsplit_once(':') else {
            continue;
        };
        if !lport.eq_ignore_ascii_case(&port_hex) {
            continue;
        }
        if let Some(rem) = want_rem {
            match parse_hex_sockaddr(fields[2]) {
                Some(parsed) if parsed == rem => {}
                _ => continue,
            }
        }
        if let Ok(inode) = fields[9].parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

/// Port-only convenience wrapper (used by the unit tests).
#[cfg(test)]
pub(crate) fn parse_proc_net_for_port(content: &str, src_port: u16) -> Option<u64> {
    parse_proc_net_match(content, src_port, None)
}

/// Parse a `/proc/net` hex socket address: `"0100007F:1F90"` (IPv4) or a 32-hex
/// IPv6 form. The address is little-endian; the port is big-endian hex.
fn parse_hex_sockaddr(s: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = s.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    match addr_hex.len() {
        8 => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())), port))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&addr_hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

// ── inode → PID ──────────────────────────────────────────────────────────────

/// Walk `/proc/*/fd/*`, readlink each fd, match "socket:[<inode>]".
/// Returns the PID of the owning process.
fn inode_to_pid(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");

    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Only numeric dirs (PIDs); skip /proc/{net,self,cpuinfo,...} non-PID entries.
        // (Using `?` here would abort the whole scan on the first non-numeric entry.)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_entries.flatten() {
            if let Ok(link) = fs::read_link(fd_entry.path()) {
                if link.to_string_lossy() == target {
                    return Some(pid);
                }
            }
        }
    }
    None
}

// ── cgroup path → cgroupid ────────────────────────────────────────────────────

/// Open the cgroup directory and call `name_to_handle_at` to retrieve the cgroup
/// inode, which equals the id returned by `bpf_skb_cgroup_id()`. Used by the
/// enforcement / smoke paths after they create the dedicated cgroup.
///
/// Returns `None` if the directory does not exist or the syscall fails.
pub(crate) fn cgroup_path_to_id(cgroup_path: &str) -> Option<u64> {
    use std::ffi::CString;

    const MAX_HANDLE_SZ: usize = 128;

    #[repr(C)]
    struct FileHandle {
        handle_bytes: u32,
        handle_type: i32,
        f_handle: [u8; MAX_HANDLE_SZ],
    }

    let cpath = CString::new(cgroup_path).ok()?;
    let mut handle = FileHandle {
        handle_bytes: MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0u8; MAX_HANDLE_SZ],
    };
    let mut mount_id: libc::c_int = 0;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD as libc::c_long,
            cpath.as_ptr(),
            &mut handle as *mut FileHandle,
            &mut mount_id as *mut libc::c_int,
            0 as libc::c_long, // flags = 0 — resolve the path directly
        )
    };

    if ret != 0 || handle.handle_bytes < 8 {
        return None;
    }
    let cgroupid = u64::from_le_bytes(handle.f_handle[..8].try_into().ok()?);
    Some(cgroupid)
}

// ── Helpers: exe path + ancestor chain ───────────────────────────────────────

/// Readlink `/proc/<pid>/exe` to get the absolute executable path.
fn read_exe_path(pid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
}

/// Read parent PIDs up to `depth` levels via `/proc/<pid>/status` `PPid:` field.
/// Returns exe paths for each ancestor found. Paths are NOT case-folded — Linux
/// filesystems are case-sensitive, matching `exe_path` (raw) so the core policy
/// app-path matcher sees consistent casing on both fields.
fn read_ancestor_paths(pid: u32, depth: usize) -> Vec<String> {
    let mut paths = Vec::new();
    let mut current_pid = pid;
    for _ in 0..depth {
        let ppid = match read_ppid(current_pid) {
            Some(p) if p > 1 => p,
            _ => break,
        };
        if let Some(path) = read_exe_path(ppid) {
            paths.push(path);
        }
        current_pid = ppid;
    }
    paths
}

/// Read the `PPid:` field from `/proc/<pid>/status`.
fn read_ppid(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_tcp_parse_fixture() {
        // Local port 0x1F90 = 8080 decimal.
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let inode = parse_proc_net_for_port(fixture, 8080);
        assert_eq!(inode, Some(12345), "should parse inode 12345 for port 8080");
    }

    #[test]
    fn proc_net_tcp_parse_no_match() {
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";
        // Port 9090 = 0x2382 — not present in fixture.
        let inode = parse_proc_net_for_port(fixture, 9090);
        assert_eq!(inode, None);
    }

    #[test]
    fn proc_net_tcp6_parse_fixture() {
        // IPv6 /proc/net/tcp6: local_address is 32 hex chars + ":PORT". Port 0x0050 = 80.
        let fixture = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0\n";
        let inode = parse_proc_net_for_port(fixture, 80);
        assert_eq!(inode, Some(55555));
    }

    #[test]
    fn proc_net_match_with_remote() {
        // local 0100007F:1F90 = 127.0.0.1:8080 ; rem 08080808:01BB = 8.8.8.8:443
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                        0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert_eq!(parse_proc_net_match(fixture, 8080, Some(dst)), Some(12345));
        // Wrong remote → no match even though local port matches.
        let wrong: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(parse_proc_net_match(fixture, 8080, Some(wrong)), None);
        // No remote constraint → matches on local port alone.
        assert_eq!(parse_proc_net_match(fixture, 8080, None), Some(12345));
    }
}
