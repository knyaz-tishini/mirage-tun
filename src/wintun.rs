use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    process::Command,
    ptr,
    sync::Arc,
};
use libloading::{Library, Symbol};
use tracing::{debug, info, warn};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Threading::WaitForSingleObject,
};
use crate::error::{Result, TunError};

// ── Wintun opaque handle types ─────────────────────────────────────────────

/// Opaque Wintun adapter handle (`WINTUN_ADAPTER_HANDLE` in wintun.h).
#[repr(transparent)]
struct WintunAdapter(*mut std::ffi::c_void);
unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

/// Opaque Wintun session handle (`WINTUN_SESSION_HANDLE` in wintun.h).
#[repr(transparent)]
struct WintunSession(*mut std::ffi::c_void);
unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

// ── Function pointer types (wintun.h) ─────────────────────────────────────

type FnCreateAdapter = unsafe extern "C" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const std::ffi::c_void,
) -> *mut std::ffi::c_void;

type FnOpenAdapter = unsafe extern "C" fn(name: *const u16) -> *mut std::ffi::c_void;

type FnCloseAdapter = unsafe extern "C" fn(adapter: *mut std::ffi::c_void);

type FnStartSession = unsafe extern "C" fn(
    adapter: *mut std::ffi::c_void,
    capacity: u32,
) -> *mut std::ffi::c_void;

type FnEndSession = unsafe extern "C" fn(session: *mut std::ffi::c_void);

type FnReceivePacket = unsafe extern "C" fn(
    session: *mut std::ffi::c_void,
    packet_size: *mut u32,
) -> *mut u8;

type FnReleaseReceivePacket =
    unsafe extern "C" fn(session: *mut std::ffi::c_void, packet: *mut u8);

type FnAllocateSendPacket = unsafe extern "C" fn(
    session: *mut std::ffi::c_void,
    packet_size: u32,
) -> *mut u8;

type FnSendPacket =
    unsafe extern "C" fn(session: *mut std::ffi::c_void, packet: *mut u8);

type FnGetReadWaitEvent =
    unsafe extern "C" fn(session: *mut std::ffi::c_void) -> HANDLE;

// ── Ring buffer capacity ───────────────────────────────────────────────────

/// Wintun ring buffer size: 0x20000 (131072 bytes, minimum 0x20000, max 0x4000000).
const WINTUN_RING_CAPACITY: u32 = 0x0020_0000; // 2 MiB

// ── WintunShared ─────────────────────────────────────────────────────────────

pub(crate) struct WintunShared {
    /// Loaded wintun.dll — must outlive adapter and session handles.
    _lib: Library,
    adapter: WintunAdapter,
    session: WintunSession,
    fn_receive: FnReceivePacket,
    fn_release: FnReleaseReceivePacket,
    fn_alloc_send: FnAllocateSendPacket,
    fn_send: FnSendPacket,
    fn_get_event: FnGetReadWaitEvent,
    fn_end_session: FnEndSession,
    fn_close_adapter: FnCloseAdapter,
}

// Safety: Wintun receive and send ring buffers are independent and thread-safe.
unsafe impl Send for WintunShared {}
unsafe impl Sync for WintunShared {}

impl Drop for WintunShared {
    fn drop(&mut self) {
        // Safety: handles are valid until Drop runs; library outlives them
        // because `_lib` is the last field dropped.
        unsafe {
            (self.fn_end_session)(self.session.0);
            (self.fn_close_adapter)(self.adapter.0);
        }
        info!("Wintun session and adapter closed");
    }
}

// ── WintunReader / WintunWriter ──────────────────────────────────────────────

/// Read-only half of a split Wintun device.
pub struct WintunReader {
    pub(crate) shared: Arc<WintunShared>,
}

/// Write-only half of a split Wintun device.
pub struct WintunWriter {
    pub(crate) shared: Arc<WintunShared>,
}

// Safety: the underlying Wintun API is thread-safe for concurrent read/write.
unsafe impl Send for WintunReader {}
unsafe impl Send for WintunWriter {}

impl WintunReader {
    /// Spawn a dedicated OS thread that reads packets from Wintun in a blocking
    /// loop and sends them over an mpsc channel.  Returns the receiving half.
    ///
    /// The thread exits when the WintunShared is dropped (session closed → recv
    /// returns NULL) or when the channel receiver is dropped.
    pub fn start_reader_thread(&self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let shared = Arc::clone(&self.shared);
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        std::thread::Builder::new()
            .name("wintun-reader".into())
            .spawn(move || {
                let event = unsafe { (shared.fn_get_event)(shared.session.0) };
                info!(
                    "wintun-reader thread: session=0x{:x} event=0x{:x}",
                    shared.session.0 as usize, event as usize
                );

                loop {
                    let wait_result = unsafe { WaitForSingleObject(event, 5000) };
                    // WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 258
                    if wait_result != 0 && wait_result != 258 {
                        warn!("wintun-reader: WaitForSingleObject returned {wait_result}, exiting");
                        break;
                    }

                    let mut pkt_size: u32 = 0;
                    let pkt_ptr = unsafe { (shared.fn_receive)(shared.session.0, &mut pkt_size) };

                    if pkt_ptr.is_null() {
                        continue; // timeout or spurious wake
                    }

                    let len = pkt_size as usize;
                    let data = unsafe { std::slice::from_raw_parts(pkt_ptr, len).to_vec() };
                    unsafe { (shared.fn_release)(shared.session.0, pkt_ptr) };

                    if tx.blocking_send(data).is_err() {
                        info!("wintun-reader: channel closed, exiting");
                        break;
                    }
                }
                info!("wintun-reader thread exiting");
            })
            .expect("wintun-reader thread spawn failed: OS thread limit reached or name contains NUL");

        rx
    }
}

impl WintunWriter {
    /// Write one IP packet to Wintun.
    pub async fn send(&self, packet: Vec<u8>) -> Result<()> {
        let shared = Arc::clone(&self.shared);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let len = packet.len() as u32;
            let send_buf = unsafe { (shared.fn_alloc_send)(shared.session.0, len) };
            if send_buf.is_null() {
                return Err(TunError::Wintun(
                    "WintunAllocateSendPacket returned NULL (ring buffer full?)".to_owned(),
                ));
            }
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), send_buf, packet.len());
                (shared.fn_send)(shared.session.0, send_buf);
            }
            Ok(())
        })
        .await
        .map_err(|e| TunError::Wintun(format!("spawn_blocking panicked: {e}")))?
    }
}

// ── WintunHandle ──────────────────────────────────────────────────────────

/// Owns the Wintun adapter + session. Call `split()` to obtain reader/writer halves.
pub struct WintunHandle {
    shared: Arc<WintunShared>,
}

impl WintunHandle {
    pub async fn create(tun_name: &str, tun_addr: &str, mtu: u16) -> Result<Self> {
        let name = tun_name.to_owned();
        let addr = tun_addr.to_owned();
        let shared = tokio::task::spawn_blocking(move || create_wintun_shared(&name, &addr, mtu))
            .await
            .map_err(|e| TunError::Wintun(format!("spawn_blocking panicked: {e}")))??;
        info!(name = tun_name, addr = tun_addr, mtu, "WintunHandle created");
        Ok(Self { shared: Arc::new(shared) })
    }

    pub fn split(&self) -> (WintunReader, WintunWriter) {
        (
            WintunReader { shared: Arc::clone(&self.shared) },
            WintunWriter { shared: Arc::clone(&self.shared) },
        )
    }
}

// ── Wintun initialisation (blocking) ──────────────────────────────────────

fn create_wintun_shared(
    tun_name: &str,
    tun_addr: &str,
    mtu: u16,
) -> Result<WintunShared> {
    // Dynamically load wintun.dll.
    // Safety: we validate all function pointers immediately after loading.
    let lib = unsafe { Library::new("wintun.dll") }.map_err(|e| {
        TunError::Wintun(format!(
            "failed to load wintun.dll: {e}. \
             Place wintun.dll next to the executable or on PATH."
        ))
    })?;

    // Load all required function pointers.
    let fn_create: Symbol<FnCreateAdapter> = unsafe { lib.get(b"WintunCreateAdapter\0") }
        .map_err(|e| TunError::Wintun(format!("WintunCreateAdapter not found: {e}")))?;
    let fn_open: Symbol<FnOpenAdapter> = unsafe { lib.get(b"WintunOpenAdapter\0") }
        .map_err(|e| TunError::Wintun(format!("WintunOpenAdapter not found: {e}")))?;
    let fn_close: Symbol<FnCloseAdapter> = unsafe { lib.get(b"WintunCloseAdapter\0") }
        .map_err(|e| TunError::Wintun(format!("WintunCloseAdapter not found: {e}")))?;
    let fn_start: Symbol<FnStartSession> = unsafe { lib.get(b"WintunStartSession\0") }
        .map_err(|e| TunError::Wintun(format!("WintunStartSession not found: {e}")))?;
    let fn_end_session: Symbol<FnEndSession> = unsafe { lib.get(b"WintunEndSession\0") }
        .map_err(|e| TunError::Wintun(format!("WintunEndSession not found: {e}")))?;
    let fn_receive: Symbol<FnReceivePacket> =
        unsafe { lib.get(b"WintunReceivePacket\0") }
            .map_err(|e| TunError::Wintun(format!("WintunReceivePacket not found: {e}")))?;
    let fn_release: Symbol<FnReleaseReceivePacket> =
        unsafe { lib.get(b"WintunReleaseReceivePacket\0") }.map_err(|e| {
            TunError::Wintun(format!("WintunReleaseReceivePacket not found: {e}"))
        })?;
    let fn_alloc_send: Symbol<FnAllocateSendPacket> =
        unsafe { lib.get(b"WintunAllocateSendPacket\0") }.map_err(|e| {
            TunError::Wintun(format!("WintunAllocateSendPacket not found: {e}"))
        })?;
    let fn_send: Symbol<FnSendPacket> = unsafe { lib.get(b"WintunSendPacket\0") }
        .map_err(|e| TunError::Wintun(format!("WintunSendPacket not found: {e}")))?;
    let fn_get_event: Symbol<FnGetReadWaitEvent> =
        unsafe { lib.get(b"WintunGetReadWaitEvent\0") }.map_err(|e| {
            TunError::Wintun(format!("WintunGetReadWaitEvent not found: {e}"))
        })?;

    // Convert the adapter name to a wide (UTF-16) string.
    let name_wide = to_wide(tun_name);
    let tunnel_type_wide = to_wide("Mirage");

    // Try to open an existing adapter first; create one if not found.
    let adapter_ptr = unsafe { fn_open(name_wide.as_ptr()) };
    let adapter_ptr = if adapter_ptr.is_null() {
        debug!(name = tun_name, "no existing Wintun adapter, creating");
        let p = unsafe { fn_create(name_wide.as_ptr(), tunnel_type_wide.as_ptr(), ptr::null()) };
        if p.is_null() {
            return Err(TunError::Wintun(format!(
                "WintunCreateAdapter failed for '{}' (check admin privileges and driver install)",
                tun_name
            )));
        }
        p
    } else {
        debug!(name = tun_name, "opened existing Wintun adapter");
        adapter_ptr
    };

    let adapter = WintunAdapter(adapter_ptr);

    // Assign IP address via netsh before starting the session.
    assign_ip_address(tun_name, tun_addr, mtu)?;

    // Wait for the adapter to stabilize.
    wait_interface_ready(tun_name);

    // Start the Wintun session.
    let session_ptr = unsafe { fn_start(adapter.0, WINTUN_RING_CAPACITY) };
    if session_ptr.is_null() {
        unsafe { fn_close(adapter.0) };
        return Err(TunError::Wintun(
            "WintunStartSession failed (ring buffer too large or driver error?)".to_owned(),
        ));
    }

    let session = WintunSession(session_ptr);

    // Copy function pointers out of the Symbol wrappers (which borrow `lib`).
    // Safety: the functions remain valid as long as `lib` is alive.
    let fn_receive = *fn_receive;
    let fn_release = *fn_release;
    let fn_alloc_send = *fn_alloc_send;
    let fn_send = *fn_send;
    let fn_get_event = *fn_get_event;
    let fn_end_session = *fn_end_session;
    let fn_close_adapter = *fn_close;

    Ok(WintunShared {
        _lib: lib,
        adapter,
        session,
        fn_receive,
        fn_release,
        fn_alloc_send,
        fn_send,
        fn_get_event,
        fn_end_session,
        fn_close_adapter,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn assign_ip_address(tun_name: &str, tun_addr: &str, mtu: u16) -> Result<()> {
    let (addr_str, prefix_str) = tun_addr
        .split_once('/')
        .ok_or_else(|| TunError::Wintun(format!(
            "tun_addr '{}' is not in CIDR notation",
            tun_addr
        )))?;

    let prefix_len: u8 = prefix_str.parse().map_err(|_| {
        TunError::Wintun(format!(
            "invalid prefix length in tun_addr '{}'",
            tun_addr
        ))
    })?;

    let netmask = prefix_to_netmask(prefix_len);

    run_netsh(&[
        "interface", "ip", "set", "address",
        tun_name, "static", addr_str, &netmask,
    ])?;

    let mtu_str = format!("mtu={mtu}");
    if let Err(e) = run_netsh(&[
        "interface", "ipv4", "set", "subinterface",
        tun_name, &mtu_str, "store=persistent",
    ]) {
        warn!("failed to set MTU (non-fatal): {e}");
    }

    if let Err(e) = run_netsh(&[
        "interface", "ip", "set", "dns",
        tun_name, "static", addr_str,
    ]) {
        warn!("failed to set DNS on TUN (non-fatal): {e}");
    }

    info!(name = tun_name, addr = addr_str, mask = %netmask, mtu, "IP address assigned");
    Ok(())
}

fn wait_interface_ready(tun_name: &str) {
    for attempt in 0..10u32 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        if let Ok(out) = Command::new("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.contains(tun_name) && line.to_lowercase().contains("connected") {
                    info!("Wintun interface '{tun_name}' ready after {attempt} polls");
                    return;
                }
            }
        }
    }
    warn!("Wintun interface '{tun_name}' not confirmed ready after 3 s, proceeding anyway");
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn prefix_to_netmask(prefix_len: u8) -> String {
    let bits = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len.min(32))
    };
    let [a, b, c, d] = bits.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

fn run_netsh(args: &[&str]) -> Result<()> {
    let label = format!("netsh {}", args.join(" "));
    debug!(cmd = %label, "WintunHandle: running netsh");

    let out = Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| TunError::Io { source: e })?;

    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Err(TunError::Wintun(format!(
        "netsh failed ({label}): {stdout}{stderr}"
    )))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_24() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
    }

    #[test]
    fn netmask_16() {
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
    }

    #[test]
    fn netmask_0() {
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
    }

    #[test]
    fn wide_null_terminated() {
        let w = to_wide("hi");
        assert_eq!(w.last(), Some(&0u16));
        assert_eq!(w.len(), 3); // 'h', 'i', NUL
    }
}
