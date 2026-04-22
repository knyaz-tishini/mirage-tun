use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Normalized (lowercase, forward-slash) exe path of a process and its ancestors.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Full Win32 path, lowercased, backslashes replaced with forward slashes.
    pub exe_path: String,
    /// Parent chain, up to 5 levels, same normalization.
    pub ancestor_paths: Vec<String>,
}

const PID_CACHE_TTL: Duration = Duration::from_secs(30);
const PID_CACHE_MAX: usize = 512;

struct PidCache {
    /// pid → (exe_path_normalized, ancestor_paths_normalized, inserted_at)
    entries: HashMap<u32, (String, Vec<String>, Instant)>,
}

impl PidCache {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    fn get(&self, pid: u32) -> Option<(String, Vec<String>)> {
        if let Some((path, ancestors, ts)) = self.entries.get(&pid) {
            if ts.elapsed() < PID_CACHE_TTL {
                return Some((path.clone(), ancestors.clone()));
            }
        }
        None
    }

    fn insert(&mut self, pid: u32, path: String, ancestors: Vec<String>) {
        if self.entries.len() >= PID_CACHE_MAX {
            // Evict the oldest entry
            let oldest = self.entries
                .iter()
                .min_by_key(|(_, (_, _, ts))| *ts)
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(pid, (path, ancestors, Instant::now()));
    }

    fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }
}

pub struct ProcessResolver {
    cache: Mutex<PidCache>,
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self { cache: Mutex::new(PidCache::new()) }
    }

    /// Looks up the process owning the TCP connection identified by `src_port` and `dst`.
    /// Returns `None` gracefully on any lookup failure.
    /// Must be called from a `spawn_blocking` context — uses synchronous Win32 APIs.
    pub fn resolve(&self, src_port: u16, dst: SocketAddr) -> Option<ProcessInfo> {
        #[cfg(windows)]
        {
            self.resolve_windows(src_port, dst)
        }
        #[cfg(not(windows))]
        {
            let _ = (src_port, dst);
            None
        }
    }

    #[cfg(windows)]
    fn resolve_windows(&self, src_port: u16, dst: SocketAddr) -> Option<ProcessInfo> {
        let pid = match find_pid_in_tcp_table(src_port, dst) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("process_info: tcp table lookup failed: {e}");
                return None;
            }
        };

        // Check cache first
        {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((exe_path, ancestor_paths)) = cache.get(pid) {
                return Some(ProcessInfo { pid, exe_path, ancestor_paths });
            }
        }

        let exe_path = match exe_path_for_pid(pid) {
            Ok(p) => normalize_path(&p),
            Err(e) => {
                tracing::warn!("process_info: exe_path_for_pid({pid}) failed: {e}");
                return None;
            }
        };

        let ancestor_paths = get_ancestor_paths(pid, self);

        {
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.insert(pid, exe_path.clone(), ancestor_paths.clone());
        }

        Some(ProcessInfo { pid, exe_path, ancestor_paths })
    }

    #[cfg(windows)]
    fn get_cached_exe_path(&self, pid: u32) -> Option<String> {
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.get(pid).map(|(path, _)| path)
    }

    #[cfg(windows)]
    fn evict_pid(&self, pid: u32) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.remove(pid);
    }
}

/// Normalize a Win32 path: lowercase + replace backslashes with forward slashes.
pub(crate) fn normalize_path(p: &str) -> String {
    p.to_lowercase().replace('\\', "/")
}

// ── Windows-only implementation ───────────────────────────────────────────────

#[cfg(windows)]
fn find_pid_in_tcp_table(src_port: u16, dst: SocketAddr) -> Result<u32, String> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };

    let dst_v4 = match dst.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("IPv6 not supported for app lookup".into()),
    };

    // AF_INET = 2
    const AF_INET: u32 = 2;

    // First call: get required buffer size
    let mut size: u32 = 0;
    let ret = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0, // bOrder = FALSE
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!("GetExtendedTcpTable size probe returned {ret}"));
    }

    // Allocate buffer with some extra margin in case table grows between calls
    let buf_size = (size as usize).saturating_add(1024);
    let mut buf: Vec<u8> = vec![0u8; buf_size];
    let mut actual_size = buf_size as u32;

    let ret = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _,
            &mut actual_size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return Err(format!("GetExtendedTcpTable failed: {ret}"));
    }

    // Parse the table header
    if buf.len() < size_of::<u32>() {
        return Err("tcp table buffer too small for header".into());
    }

    let num_entries = unsafe {
        let table_ptr = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        (*table_ptr).dwNumEntries
    };

    let header_size = size_of::<u32>(); // dwNumEntries
    let row_size = size_of::<MIB_TCPROW_OWNER_PID>();
    let required = header_size + num_entries as usize * row_size;

    if buf.len() < required {
        return Err(format!(
            "tcp table buffer too small: have={} need={}",
            buf.len(),
            required
        ));
    }

    let dst_addr_ne = u32::from_ne_bytes(dst_v4.octets()); // network-order as stored in table
    let dst_port_be = dst.port().to_be() as u32;

    for i in 0..num_entries as usize {
        let row_ptr = unsafe {
            let base = buf.as_ptr().add(header_size + i * row_size);
            &*(base as *const MIB_TCPROW_OWNER_PID)
        };

        // dwLocalPort is network byte order in the low 16 bits of a DWORD
        let local_port_host = u16::from_be((row_ptr.dwLocalPort & 0xFFFF) as u16);
        // dwRemotePort same layout
        let remote_port_host = u16::from_be((row_ptr.dwRemotePort & 0xFFFF) as u16);

        // dwLocalAddr / dwRemoteAddr are stored in network byte order (as u32 LE on x86,
        // but the 4 bytes themselves form the big-endian IP).  Ipv4Addr::from takes a
        // big-endian [u8;4], so we can reinterpret the u32 bytes directly.
        let remote_addr = Ipv4Addr::from(row_ptr.dwRemoteAddr.to_ne_bytes());

        if local_port_host == src_port && remote_port_host == dst.port() && remote_addr == dst_v4 {
            return Ok(row_ptr.dwOwningPid);
        }

        // Also try matching with only src_port — some connections show as 0 remote when not yet
        // fully established; fall through on those.
        let _ = (dst_addr_ne, dst_port_be); // suppress unused warning
    }

    Err(format!(
        "connection not found in tcp table: src_port={src_port} dst={dst}"
    ))
}

#[cfg(windows)]
fn exe_path_for_pid(pid: u32) -> std::io::Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = [0u16; 512];
    let mut size = buf.len() as u32;

    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size)
    };

    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(String::from_utf16_lossy(&buf[..size as usize]))
}

/// Walk parent PID chain upward, up to 5 levels, collecting normalized exe paths.
#[cfg(windows)]
fn get_ancestor_paths(target_pid: u32, resolver: &ProcessResolver) -> Vec<String> {
    let parent_map = match build_parent_map() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("process_info: build_parent_map failed: {e}");
            return vec![];
        }
    };

    let mut ancestors = Vec::new();
    let mut current_pid = target_pid;

    for _ in 0..5 {
        let parent_pid = match parent_map.get(&current_pid) {
            Some(&p) if p != 0 && p != current_pid => p,
            _ => break,
        };

        // Try cache first, then live query
        let path = if let Some(cached) = resolver.get_cached_exe_path(parent_pid) {
            Some(cached)
        } else {
            match exe_path_for_pid(parent_pid) {
                Ok(p) => {
                    let normalized = normalize_path(&p);
                    // Insert just the path into cache (no ancestors for ancestors themselves)
                    {
                        let mut cache = resolver.cache.lock().unwrap_or_else(|p| p.into_inner());
                        if cache.get(parent_pid).is_none() {
                            cache.insert(parent_pid, normalized.clone(), vec![]);
                        }
                    }
                    Some(normalized)
                }
                Err(_) => {
                    resolver.evict_pid(parent_pid);
                    None
                }
            }
        };

        if let Some(p) = path {
            ancestors.push(p);
        }

        current_pid = parent_pid;
    }

    ancestors
}

/// Build a HashMap<pid, parent_pid> from a Toolhelp snapshot.
#[cfg(windows)]
fn build_parent_map() -> Result<HashMap<u32, u32>, String> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(format!(
            "CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut map = HashMap::new();

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let first_ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    if first_ok != 0 {
        map.insert(entry.th32ProcessID, entry.th32ParentProcessID);

        loop {
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let ok = unsafe { Process32NextW(snapshot, &mut entry) };
            if ok == 0 {
                break;
            }
            map.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        }
    }

    unsafe { CloseHandle(snapshot) };

    Ok(map)
}
