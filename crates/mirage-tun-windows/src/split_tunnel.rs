//! The split-tunnel driver: an application that leaves the tunnel.
//!
//! The network bypass (`crate::bypass`) is a hole in the routing: it lets a
//! DESTINATION out of the tunnel.  This module is the other half — it lets an
//! APPLICATION out, by image.
//!
//! The work is done by the Mullvad split-tunnel driver
//! (`mullvad-split-tunnel.sys`, upstream revision `v1.3.0.0`).  The driver
//! is a WFP callout: it watches the processes, and for the ones on the list it
//! permits the traffic that would otherwise be forced into the tunnel, and
//! blocks the traffic that would go into it.
//!
//! The protocol is the driver's own:
//!
//! ```text
//! open the device  ->  GET_STATE  ->  RESET (if it is not STARTED)
//!                   ->  INITIALIZE (two WFP sublayer GUIDs)
//!                   ->  REGISTER_PROCESSES (the whole machine, once)
//!                   ->  REGISTER_IP_ADDRESSES (tunnel + internet)
//!                   ->  SET_CONFIGURATION (the images to exclude)
//!                   ->  DEQUEUE_EVENT (a thread, until RESET)
//! ```
//!
//! The order matters: the driver is a state machine, and every request that
//! does not belong to the current state is refused.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWP_BYTE_BLOB, FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_SESSION0,
    FWPM_SUBLAYER0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, QueryDosDeviceW};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::Services::{OpenServiceW, StartServiceW};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The device the driver exposes.
const DEVICE_PATH: &str = r"\\.\MULLVADSPLITTUNNEL";

/// IOCTL codes, as the driver defines them (`CTL_CODE(0x8000, fn, method, any)`).
const IOCTL_INITIALIZE: u32 = 0x8000_0004;
const IOCTL_DEQUEUE_EVENT: u32 = 0x8000_0008;
const IOCTL_REGISTER_IP_ADDRESSES: u32 = 0x8000_0010;
const IOCTL_REGISTER_PROCESSES: u32 = 0x8000_000c;
const IOCTL_SET_CONFIGURATION: u32 = 0x8000_0018;
const IOCTL_CLEAR_CONFIGURATION: u32 = 0x8000_0023;
const IOCTL_GET_STATE: u32 = 0x8000_0024;
const IOCTL_RESET: u32 = 0x8000_002F;

/// The driver's states.
const STATE_STARTED: u64 = 1;
const STATE_INITIALIZED: u64 = 2;
const STATE_READY: u64 = 3;
const STATE_ENGAGED: u64 = 4;

/// The provider WE own: the driver's own provider appears only inside
/// `INITIALIZE`, and a sublayer needs a provider that already exists.
const PROVIDER_KEY: GUID = GUID::from_u128(0x6f3c_1b54_6a2e_4f1d_9e2b_2a5d_7c8e_9f01);
/// The sublayer the driver's ordinary filters live in.
///
/// The GUIDs are ours, not Mullvad's: the machine may already carry the
/// sublayers of another client, and the driver takes whatever GUIDs it is
/// given.
const BASELINE_SUBLAYER: GUID = GUID::from_u128(0x9a4d_7c62_3e51_4b28_9c7d_6f0a_2b8e_5d13);
/// The sublayer the driver's DNS filters live in.
const DNS_SUBLAYER: GUID = GUID::from_u128(0x2f6c_81ab_5d47_4e93_8b12_0c7a_9e4d_3f58);

/// `STATUS_CANCELLED` — the driver's answer to a request that was cancelled
/// (the `RESET` cancels the pending events).
const STATUS_CANCELLED: u32 = 0xc000_0120;

/// The firewall's answer when an object with that key is already there.
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

/// The event the driver sends when a process starts or stops being excluded.
const EVENT_START_SPLITTING: u32 = 0;
const EVENT_STOP_SPLITTING: u32 = 1;

/// A failure of the split-tunnel path.
#[derive(Debug)]
pub enum SplitTunnelError {
    /// The driver is not there (not installed, or not started).
    DeviceUnavailable(String),
    /// The driver refused a request.
    Driver(String, u32),
    /// The WFP layer refused.
    Wfp(String, u32),
    /// The list of applications could not be turned into device paths.
    NoSuchApplication(String),
    /// Anything else the platform said.
    Platform(io::Error),
}

impl fmt::Display for SplitTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitTunnelError::DeviceUnavailable(m) => write!(f, "the split-tunnel device is not there: {m}"),
            SplitTunnelError::Driver(m, code) => write!(f, "the split-tunnel driver refused: {m} (0x{code:08X})"),
            SplitTunnelError::Wfp(m, code) => write!(f, "the firewall refused: {m} (0x{code:08X})"),
            SplitTunnelError::NoSuchApplication(m) => write!(f, "no running application matches '{m}'"),
            SplitTunnelError::Platform(e) => write!(f, "the platform refused: {e}"),
        }
    }
}

impl std::error::Error for SplitTunnelError {}

impl From<io::Error> for SplitTunnelError {
    fn from(e: io::Error) -> Self {
        SplitTunnelError::Platform(e)
    }
}

/// The header of a configuration or a process list.
#[repr(C)]
#[derive(Clone, Copy)]
struct ListHeader {
    num_entries: u64,
    total_length: u64,
}

/// One image on the exclude list.
#[repr(C)]
#[derive(Clone, Copy)]
struct ConfigurationEntry {
    image_name_offset: u64,
    image_name_length: u16,
    _pad: [u8; 6],
}

/// One process of the machine.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry {
    process_id: u64,
    parent_process_id: u64,
    image_name_offset: u64,
    image_name_length: u16,
    _pad: [u8; 6],
}

/// The addresses the driver needs to tell the tunnel from the internet.
#[repr(C)]
#[derive(Clone, Copy)]
struct IpAddresses {
    tunnel_v4: u32,
    internet_v4: u32,
    tunnel_v6: [u8; 16],
    internet_v6: [u8; 16],
}

impl IpAddresses {
    fn new(tunnel: Ipv4Addr, internet: Ipv4Addr) -> Self {
        Self {
            tunnel_v4: u32::from_ne_bytes(tunnel.octets()),
            internet_v4: u32::from_ne_bytes(internet.octets()),
            tunnel_v6: [0; 16],
            internet_v6: [0; 16],
        }
    }

    /// The forty bytes the driver reads.
    fn bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..4].copy_from_slice(&self.tunnel_v4.to_ne_bytes());
        out[4..8].copy_from_slice(&self.internet_v4.to_ne_bytes());
        out[8..24].copy_from_slice(&self.tunnel_v6);
        out[24..40].copy_from_slice(&self.internet_v6);
        out
    }
}

/// The two sublayer GUIDs the driver keeps.
#[repr(C)]
#[derive(Clone, Copy)]
struct SublayerGuids {
    baseline: GUID,
    dns: GUID,
}

/// Pack a list of images into the driver's buffer.
///
/// The layout is a header, the entries, and then the strings; an entry's
/// offset is counted from the beginning of the string area.
fn pack_configuration(paths: &[Vec<u16>]) -> Vec<u8> {
    let entry_size = mem::size_of::<ConfigurationEntry>();
    let header_size = mem::size_of::<ListHeader>();
    let strings: Vec<u8> = paths
        .iter()
        .flat_map(|p| p.iter().flat_map(|c| c.to_le_bytes()))
        .collect();
    let mut offsets = Vec::with_capacity(paths.len());
    let mut at = 0usize;
    for p in paths {
        offsets.push(at);
        at += p.len() * 2;
    }
    let total = header_size + paths.len() * entry_size + strings.len();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(paths.len() as u64).to_ne_bytes());
    buf.extend_from_slice(&(total as u64).to_ne_bytes());
    for (path, offset) in paths.iter().zip(offsets) {
        buf.extend_from_slice(&(offset as u64).to_ne_bytes());
        buf.extend_from_slice(&((path.len() * 2) as u16).to_ne_bytes());
        buf.extend_from_slice(&[0u8; 6]);
    }
    buf.extend_from_slice(&strings);
    buf
}

/// Pack the processes of the machine into the driver's buffer.
fn pack_processes(processes: &[(u32, u32, Vec<u16>)]) -> Vec<u8> {
    let entry_size = mem::size_of::<ProcessEntry>();
    let header_size = mem::size_of::<ListHeader>();
    let strings: Vec<u8> = processes
        .iter()
        .flat_map(|(_, _, p)| p.iter().flat_map(|c| c.to_le_bytes()))
        .collect();
    let mut offsets = Vec::with_capacity(processes.len());
    let mut at = 0usize;
    for (_, _, p) in processes {
        offsets.push(at);
        at += p.len() * 2;
    }
    let total = header_size + processes.len() * entry_size + strings.len();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(processes.len() as u64).to_ne_bytes());
    buf.extend_from_slice(&(total as u64).to_ne_bytes());
    for ((pid, ppid, path), offset) in processes.iter().zip(offsets) {
        buf.extend_from_slice(&(*pid as u64).to_ne_bytes());
        buf.extend_from_slice(&(*ppid as u64).to_ne_bytes());
        buf.extend_from_slice(&(offset as u64).to_ne_bytes());
        buf.extend_from_slice(&((path.len() * 2) as u16).to_ne_bytes());
        buf.extend_from_slice(&[0u8; 6]);
    }
    buf.extend_from_slice(&strings);
    buf
}

/// A handle that may cross a thread boundary.
///
/// The driver's device and the firewall engine are used by one thread at a
/// time; the handle itself is just a number the kernel knows.
#[derive(Clone, Copy)]
struct SharedHandle(HANDLE);

// SAFETY: the handle is only used through the driver and the firewall, both
// of which are thread safe, and the value is copied, never aliased.
unsafe impl Send for SharedHandle {}
unsafe impl Sync for SharedHandle {}

/// The WFP session we own while the driver is engaged.
struct WfpScope {
    engine: SharedHandle,
}

impl WfpScope {
    fn open() -> Result<Self, SplitTunnelError> {
        let mut session: FWPM_SESSION0 = unsafe { mem::zeroed() };
        // The session is NOT dynamic: the driver adds its filters from its
        // own session, and it may only do that into a sublayer that belongs
        // to a persistent session.  A dynamic one is private to us, and the
        // driver would answer that the call came from the wrong session.
        session.flags = 0;
        let mut engine: HANDLE = ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT as u32,
                ptr::null(),
                &session,
                &mut engine,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("the engine would not open".into(), status));
        }
        Ok(Self { engine: SharedHandle(engine) })
    }

    /// Add our provider and the two sublayers the driver asked for.
    fn add_sublayers(&self) -> Result<(), SplitTunnelError> {
        match self.try_add_sublayers() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Something of ours is left over from a run that died.  Take
                // it away and try once more.
                if !matches!(e, SplitTunnelError::Wfp(_, FWP_E_ALREADY_EXISTS)) {
                    return Err(e);
                }
                self.remove_sublayers();
                self.try_add_sublayers()
            }
        }
    }

    fn try_add_sublayers(&self) -> Result<(), SplitTunnelError> {
        let status = unsafe { FwpmTransactionBegin0(self.engine.0, 0) };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("no transaction".into(), status));
        }
        let result = self.add_sublayers_inner();
        if result.is_err() {
            unsafe { FwpmTransactionAbort0(self.engine.0) };
            return result;
        }
        let status = unsafe { FwpmTransactionCommit0(self.engine.0) };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("the transaction would not commit".into(), status));
        }
        Ok(())
    }

    fn add_sublayers_inner(&self) -> Result<(), SplitTunnelError> {
        let provider_name: Vec<u16> = wide_z("mirage split tunnel");
        let provider_desc: Vec<u16> = wide_z("the sublayers the split-tunnel driver hangs its filters on");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: provider_name.as_ptr() as *mut u16,
                description: provider_desc.as_ptr() as *mut u16,
            },
            flags: 0,
            providerData: FWP_BYTE_BLOB {
                data: ptr::null_mut(),
                size: 0,
            },
            serviceName: ptr::null_mut(),
        };
        let status = unsafe { FwpmProviderAdd0(self.engine.0, &provider, ptr::null_mut()) };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("the provider would not be added".into(), status));
        }

        let baseline_name: Vec<u16> = wide_z("mirage split tunnel baseline");
        let baseline_desc: Vec<u16> = wide_z("the split-tunnel filters");
        let mut provider_key = PROVIDER_KEY;
        let provider_key_ptr: *mut GUID = &mut provider_key;
        let baseline = FWPM_SUBLAYER0 {
            subLayerKey: BASELINE_SUBLAYER,
            displayData: FWPM_DISPLAY_DATA0 {
                name: baseline_name.as_ptr() as *mut u16,
                description: baseline_desc.as_ptr() as *mut u16,
            },
            flags: 0,
            providerKey: provider_key_ptr,
            providerData: FWP_BYTE_BLOB {
                data: ptr::null_mut(),
                size: 0,
            },
            weight: 0xffff,
        };
        let status = unsafe { FwpmSubLayerAdd0(self.engine.0, &baseline, ptr::null_mut()) };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("the baseline sublayer would not be added".into(), status));
        }

        let dns_name: Vec<u16> = wide_z("mirage split tunnel dns");
        let dns_desc: Vec<u16> = wide_z("the split-tunnel DNS filters");
        let dns = FWPM_SUBLAYER0 {
            subLayerKey: DNS_SUBLAYER,
            displayData: FWPM_DISPLAY_DATA0 {
                name: dns_name.as_ptr() as *mut u16,
                description: dns_desc.as_ptr() as *mut u16,
            },
            flags: 0,
            providerKey: provider_key_ptr,
            providerData: FWP_BYTE_BLOB {
                data: ptr::null_mut(),
                size: 0,
            },
            weight: 0xffff,
        };
        let status = unsafe { FwpmSubLayerAdd0(self.engine.0, &dns, ptr::null_mut()) };
        if status != ERROR_SUCCESS {
            return Err(SplitTunnelError::Wfp("the DNS sublayer would not be added".into(), status));
        }
        Ok(())
    }

    /// Take the provider and the sublayers back.
    fn remove_sublayers(&self) {
        let status = unsafe { FwpmTransactionBegin0(self.engine.0, 0) };
        if status != ERROR_SUCCESS {
            return;
        }
        unsafe {
            FwpmSubLayerDeleteByKey0(self.engine.0, &DNS_SUBLAYER);
            FwpmSubLayerDeleteByKey0(self.engine.0, &BASELINE_SUBLAYER);
            FwpmProviderDeleteByKey0(self.engine.0, &PROVIDER_KEY);
        }
        unsafe { FwpmTransactionCommit0(self.engine.0) };
    }
}

impl Drop for WfpScope {
    fn drop(&mut self) {
        self.remove_sublayers();
        unsafe { FwpmEngineClose0(self.engine.0) };
    }
}

/// The exclusion, live: the driver is engaged and the applications on the
/// list leave the tunnel.
pub struct SplitTunnel {
    device: SharedHandle,
    scope: WfpScope,
    stop: Arc<AtomicBool>,
    events: Option<(std::sync::mpsc::Receiver<()>, thread::JoinHandle<()>)>,
}

impl SplitTunnel {
    /// Let the applications leave the tunnel.
    ///
    /// `tunnel` is the address of the adapter, `internet` the address of the
    /// physical interface the tunnel took over from; `applications` names the
    /// images to exclude (`node.exe`, or a full path).
    pub fn engage(
        tunnel: Ipv4Addr,
        internet: Ipv4Addr,
        applications: &[String],
    ) -> Result<Self, SplitTunnelError> {
        if applications.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication("the list is empty".into()));
        }

        // The images the driver matches are NT device paths
        // (`\Device\HarddiskVolumeN\...`), so the names have to be resolved
        // against the processes that are running right now.
        //
        // One name that cannot be resolved is not a reason to give the whole
        // list up: the applications that ARE known still leave the tunnel.
        // A bare name ("node.exe") that is not running right now cannot be
        // resolved at all -- the driver gets it when the process shows up.
        let running = running_processes();
        let mut excluded: Vec<Vec<u16>> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        for wanted in applications {
            match resolve_application(wanted, &running) {
                Some(path) => excluded.push(wide(&path)),
                None => missing.push(wanted.clone()),
            }
        }
        if excluded.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication(missing.join(", ")));
        }
        if !missing.is_empty() {
            tracing::info!(
                missing = %missing.join(", "),
                "split-tunnel: these names are not running now; the rest of the list leaves the tunnel"
            );
        }

        // The sublayers must exist before the driver is initialized: the
        // driver hangs its filters on them.
        let scope = WfpScope::open()?;
        scope.add_sublayers()?;

        let device = SharedHandle(open_device()?);
        let result = Self::engage_inner(device, scope, tunnel, internet, excluded);
        match result {
            Ok(mut engaged) => Ok(engaged),
            Err(e) => {
                // The device was opened: it must be closed again, or the
                // driver stays busy for the next one.
                unsafe { CloseHandle(device.0) };
                Err(e)
            }
        }
    }

    fn engage_inner(
        device: SharedHandle,
        scope: WfpScope,
        tunnel: Ipv4Addr,
        internet: Ipv4Addr,
        excluded: Vec<Vec<u16>>,
    ) -> Result<Self, SplitTunnelError> {
        // A driver that is still holding the state of a previous client has
        // to be reset before it can be initialized again.
        let state = driver_state(device.0)?;
        if state != STATE_STARTED {
            tracing::warn!(state, "split-tunnel: the driver was not fresh, resetting it");
            let _ = ioctl(device.0, IOCTL_RESET, None, &mut []);
        }
        let state = driver_state(device.0)?;
        if state != STATE_STARTED {
            return Err(SplitTunnelError::Driver(
                "the driver would not go back to its fresh state".into(),
                state as u32,
            ));
        }

        // The two sublayers the driver will hang its filters on.
        let guids = SublayerGuids {
            baseline: BASELINE_SUBLAYER,
            dns: DNS_SUBLAYER,
        };
        let mut out: [u8; 0] = [];
        ioctl(device.0, IOCTL_INITIALIZE, Some(&guids_bytes(&guids)), &mut out)?;

        // The processes of the machine: the driver watches them from now on.
        let processes = running_processes();
        let packed = pack_processes(&processes);
        let mut out: [u8; 0] = [];
        ioctl(device.0, IOCTL_REGISTER_PROCESSES, Some(&packed), &mut out)?;

        // The addresses: which is the tunnel, which is the internet.
        let addresses = IpAddresses::new(tunnel, internet);
        let mut out: [u8; 0] = [];
        ioctl(
            device.0,
            IOCTL_REGISTER_IP_ADDRESSES,
            Some(&addresses.bytes()),
            &mut out,
        )?;

        // The images that leave the tunnel.
        let configuration = pack_configuration(&excluded);
        let mut out: [u8; 0] = [];
        ioctl(device.0, IOCTL_SET_CONFIGURATION, Some(&configuration), &mut out)?;

        // The events: the driver says who started and who stopped.
        //
        // The driver tells about every process on the machine, so the log
        // only carries the names the person asked about.
        let watched: Vec<String> = excluded
            .iter()
            .filter_map(|path| {
                let text = String::from_utf16_lossy(path);
                text.rsplit('\\').next().map(|name| name.to_lowercase())
            })
            .filter(|name| !name.is_empty())
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let events = {
            let stop = Arc::clone(&stop);
            let watched = watched.clone();
            thread::Builder::new()
                .name("mirage-split-tunnel".into())
                .spawn(move || {
                    event_loop(device, stop, watched);
                    let _ = done_tx.send(());
                })
                .ok()
        };

        let state = driver_state(device.0)?;
        tracing::info!(
            state,
            tunnel = %tunnel,
            internet = %internet,
            applications = excluded.len(),
            "split-tunnel: the applications are out of the tunnel"
        );

        Ok(Self {
            device,
            scope,
            stop,
            events: events.map(|handle| (done_rx, handle)),
        })
    }

    /// Replace the list of applications that leave the tunnel.
    pub fn set_exclusions(&mut self, applications: &[String]) -> Result<(), SplitTunnelError> {
        if applications.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication("the list is empty".into()));
        }
        let running = running_processes();
        let mut excluded: Vec<Vec<u16>> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        for wanted in applications {
            match resolve_application(wanted, &running) {
                Some(path) => excluded.push(wide(&path)),
                None => missing.push(wanted.clone()),
            }
        }
        if excluded.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication(missing.join(", ")));
        }
        let configuration = pack_configuration(&excluded);
        let mut out: [u8; 0] = [];
        ioctl(self.device.0, IOCTL_SET_CONFIGURATION, Some(&configuration), &mut out)?;
        Ok(())
    }

    /// The state the driver is in.
    pub fn state(&self) -> Result<u64, SplitTunnelError> {
        driver_state(self.device.0)
    }
}

impl Drop for SplitTunnel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The reset takes the filters down and cancels the pending event.
        let _ = ioctl(self.device.0, IOCTL_CLEAR_CONFIGURATION, None, &mut []);
        let _ = ioctl(self.device.0, IOCTL_RESET, None, &mut []);
        if let Some((done, handle)) = self.events.take() {
            // The event thread is waiting on the driver; the reset above
            // cancelled it.  If it did not come back, the handle is closed
            // anyway and the thread ends on the closed handle.
            match done.recv_timeout(Duration::from_secs(2)) {
                Ok(()) => {
                    let _ = handle.join();
                }
                Err(_) => {
                    std::mem::forget(handle);
                }
            }
        }
        unsafe { CloseHandle(self.device.0) };
    }
}

/// Open the driver's device.
fn open_device() -> Result<HANDLE, SplitTunnelError> {
    let handle = open_device_once();
    if handle.is_ok() {
        return handle;
    }
    // The driver is installed but not running: start it and try again.
    if start_driver_service() {
        thread::sleep(Duration::from_millis(500));
        return open_device_once();
    }
    Err(handle.err().unwrap_or(SplitTunnelError::DeviceUnavailable(
        "the driver is not installed".into(),
    )))
}

fn open_device_once() -> Result<HANDLE, SplitTunnelError> {
    let name: Vec<u16> = DEVICE_PATH.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            0xc000_0000, // GENERIC_READ | GENERIC_WRITE
            0x0000_0003, // FILE_SHARE_READ | FILE_SHARE_WRITE
            ptr::null::<SECURITY_ATTRIBUTES>(),
            3, // OPEN_EXISTING
            0x0000_0000,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(SplitTunnelError::DeviceUnavailable(format!(
            "the driver is not installed or not started (error {})",
            io::Error::last_os_error()
        )));
    }
    Ok(handle)
}

/// Start the driver's service, if it is installed and not running.
fn start_driver_service() -> bool {
    let name: Vec<u16> = "mullvad-split-tunnel\0".encode_utf16().collect();
    unsafe {
        let service = OpenServiceW(ptr::null_mut(), name.as_ptr(), 0x000f_01ff);
        if service.is_null() {
            return false;
        }
        let started = StartServiceW(service, 0, ptr::null()) != 0;
        CloseHandle(service);
        started
    }
}

/// One request to the driver.
fn ioctl(device: HANDLE, code: u32, input: Option<&[u8]>, output: &mut [u8]) -> Result<u32, SplitTunnelError> {
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            device,
            code,
            input.map(|b| b.as_ptr() as *const c_void).unwrap_or(ptr::null()),
            input.map(|b| b.len() as u32).unwrap_or(0),
            if output.is_empty() {
                ptr::null_mut()
            } else {
                output.as_mut_ptr() as *mut c_void
            },
            output.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(0) as u32;
        return Err(SplitTunnelError::Driver(format!("the request 0x{code:08X} failed: {err}"), raw));
    }
    Ok(returned)
}

/// The state the driver is in.
fn driver_state(device: HANDLE) -> Result<u64, SplitTunnelError> {
    let mut out = [0u8; 8];
    ioctl(device, IOCTL_GET_STATE, None, &mut out)?;
    Ok(u64::from_ne_bytes(out))
}

/// The two sublayer GUIDs as the driver wants them.
fn guids_bytes(guids: &SublayerGuids) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(unsafe { std::slice::from_raw_parts(&guids.baseline as *const GUID as *const u8, 16) });
    out[16..].copy_from_slice(unsafe { std::slice::from_raw_parts(&guids.dns as *const GUID as *const u8, 16) });
    out
}

/// The events: who started and who stopped being out of the tunnel.
///
/// The driver tells about EVERY process on the machine -- it has to, it is
/// the one that decides who leaves the tunnel. So the log only carries the
/// names the person asked about; the rest is a debug line. A log that grows
/// by megabytes a minute is a log nobody reads.
fn event_loop(device: SharedHandle, stop: Arc<AtomicBool>, watched: Vec<String>) {
    let mut buffer = vec![0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                device.0,
                IOCTL_DEQUEUE_EVENT,
                ptr::null(),
                0,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0) as u32;
            if raw == STATUS_CANCELLED || raw == 1223 {
                break;
            }
            // The handle is gone: there is nothing left to wait for.
            if raw == 6 {
                break;
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            tracing::debug!(error = %err, "split-tunnel: the event request failed, retrying");
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        let returned = returned as usize;
        if returned < 16 {
            continue;
        }
        let event_id = u32::from_ne_bytes(buffer[0..4].try_into().unwrap());
        let size = u64::from_ne_bytes(buffer[8..16].try_into().unwrap()) as usize;
        match event_id {
            EVENT_START_SPLITTING => {
                let name = event_name(&buffer[16..returned.min(16 + size)]);
                if watched.iter().any(|watched| name.to_lowercase().contains(watched)) {
                    tracing::info!(application = %name, "split-tunnel: the application left the tunnel");
                } else {
                    tracing::debug!(application = %name, "split-tunnel: an application left the tunnel");
                }
            }
            EVENT_STOP_SPLITTING => {
                let name = event_name(&buffer[16..returned.min(16 + size)]);
                if watched.iter().any(|watched| name.to_lowercase().contains(watched)) {
                    tracing::info!(application = %name, "split-tunnel: the application came back into the tunnel");
                } else {
                    tracing::debug!(application = %name, "split-tunnel: an application came back into the tunnel");
                }
            }
            _ => {
                tracing::debug!(event_id, "split-tunnel: an event from the driver");
            }
        }
    }
}

/// The name inside an event.
fn event_name(payload: &[u8]) -> String {
    if payload.len() < 16 {
        return String::new();
    }
    let length = u16::from_ne_bytes(payload[12..14].try_into().unwrap()) as usize;
    let start = 16;
    let end = (start + length).min(payload.len());
    if end <= start {
        return String::new();
    }
    let units: Vec<u16> = payload[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The processes of the machine, with their NT device paths.
fn running_processes() -> Vec<(u32, u32, Vec<u16>)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Vec::new();
    }
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        let path = device_path_of(entry.th32ProcessID);
        if let Some(path) = path {
            out.push((entry.th32ProcessID, entry.th32ParentProcessID, path));
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };
    out
}

/// The NT device path of a process: `\Device\HarddiskVolumeN\...`.
fn device_path_of(pid: u32) -> Option<Vec<u16>> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let length = unsafe { K32GetProcessImageFileNameW(handle, buffer.as_mut_ptr(), buffer.len() as u32) };
    unsafe { CloseHandle(handle) };
    if length == 0 {
        return None;
    }
    let end = buffer[..length as usize]
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(length as usize);
    Some(buffer[..end].to_vec())
}

/// Find the device path of the application the person named.
fn resolve_application(wanted: &str, running: &[(u32, u32, Vec<u16>)]) -> Option<String> {
    let wanted = wanted.trim();
    if wanted.is_empty() {
        return None;
    }
    // A full path the person wrote ("E:\MU\main.exe") is translated into the
    // device path of its own accord -- the drive alone says which volume it
    // is on. The application does NOT have to be running for that: the driver
    // takes the list of images and excludes them when they show up. Only a
    // bare name ("node.exe") needs a running process to say where it lives.
    if let Some(path) = device_path_from_dos(wanted) {
        return Some(path);
    }
    let wanted_file = wanted
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(wanted)
        .to_ascii_lowercase();
    // A full path as the person wrote it ("E:\MU\main.exe") is compared with
    // the tail of the device path ("\Device\HarddiskVolumeN\MU\main.exe"):
    // the drive is dropped, the rest must match.
    let wanted_tail = wanted.replace('/', "\\").to_ascii_lowercase();
    let wanted_tail = match wanted_tail.find(':') {
        Some(drive) => wanted_tail[drive + 1..].to_owned(),
        None => wanted_tail,
    };

    for (_, _, path) in running {
        let text = String::from_utf16_lossy(path);
        let lower = text.to_ascii_lowercase();
        let file = lower.rsplit('\\').next().unwrap_or(&lower).to_string();
        if file == wanted_file {
            return Some(text);
        }
        // A full path: the device path carries the same tail.
        if lower.ends_with(&wanted_tail) && wanted_tail.contains('\\') {
            return Some(text);
        }
    }
    None
}

/// The device path of a DOS path ("E:\MU\main.exe").
///
/// The drive is asked what volume it is, and the rest of the path is kept:
/// "\Device\HarddiskVolume3\MU\main.exe". The file itself does not have to
/// exist -- the driver excludes an image when it starts, not when it is
/// already running.
fn device_path_from_dos(wanted: &str) -> Option<String> {
    let text = wanted.trim();
    let mut chars = text.chars();
    let drive = chars.next()?;
    if !drive.is_ascii_alphabetic() {
        return None;
    }
    if chars.next()? != ':' {
        return None;
    }
    let rest = &text[2..];
    if !rest.contains('\\') && !rest.contains('/') {
        return None;
    }
    let name: Vec<u16> = format!("{}:", drive.to_ascii_uppercase()).encode_utf16().collect();
    let mut buffer = vec![0u16; 1024];
    let length = unsafe {
        QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
    };
    if length == 0 {
        return None;
    }
    let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    let device = String::from_utf16_lossy(&buffer[..end]);
    if device.is_empty() {
        return None;
    }
    let rest = rest.replace('/', "\\");
    Some(format!("{device}{rest}"))
}

/// A wide string without a terminator: the driver reads the length itself.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A wide string with a terminator: the firewall wants a C string.
fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The address of this machine on the physical interface.
///
/// The kernel is asked which local address would be used to reach the
/// gateway: that is the address the tunnel took over from.
pub fn local_address_for(gateway: IpAddr) -> Option<Ipv4Addr> {
    let gateway = match gateway {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket
        .connect(&socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(gateway), 9)))
        .ok()?;
    let local = socket.local_addr().ok()?;
    match local.as_socket() {
        Some(SocketAddr::V4(v4)) => Some(*v4.ip()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_is_packed_the_way_the_driver_reads_it() {
        let a = wide(r"\Device\HarddiskVolume2\Program Files\nodejs\node.exe");
        let b = wide(r"\Device\HarddiskVolume2\Windows\System32\svchost.exe");
        let packed = pack_configuration(&[a.clone(), b.clone()]);

        let header = ListHeader {
            num_entries: u64::from_ne_bytes(packed[0..8].try_into().unwrap()),
            total_length: u64::from_ne_bytes(packed[8..16].try_into().unwrap()),
        };
        assert_eq!(header.num_entries, 2);
        assert_eq!(header.total_length as usize, packed.len());

        let entry_size = mem::size_of::<ConfigurationEntry>();
        let mut at = mem::size_of::<ListHeader>();
        for path in [&a, &b] {
            let entry = ConfigurationEntry {
                image_name_offset: u64::from_ne_bytes(packed[at..at + 8].try_into().unwrap()),
                image_name_length: u16::from_ne_bytes(packed[at + 8..at + 10].try_into().unwrap()),
                _pad: [0; 6],
            };
            assert_eq!(entry.image_name_length as usize, path.len() * 2);
            let start = mem::size_of::<ListHeader>() + 2 * entry_size + entry.image_name_offset as usize;
            let end = start + entry.image_name_length as usize;
            let units: Vec<u16> = packed[start..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            assert_eq!(units, *path);
            at += entry_size;
        }
    }

    #[test]
    fn the_process_list_is_packed_the_way_the_driver_reads_it() {
        let processes = vec![
            (100u32, 4u32, wide(r"\Device\HarddiskVolume2\a.exe")),
            (200u32, 100u32, wide(r"\Device\HarddiskVolume2\b.exe")),
        ];
        let packed = pack_processes(&processes);
        let header = ListHeader {
            num_entries: u64::from_ne_bytes(packed[0..8].try_into().unwrap()),
            total_length: u64::from_ne_bytes(packed[8..16].try_into().unwrap()),
        };
        assert_eq!(header.num_entries, 2);
        assert_eq!(header.total_length as usize, packed.len());
        assert_eq!(mem::size_of::<ProcessEntry>(), 32);
    }

    #[test]
    fn an_empty_list_is_not_a_configuration() {
        assert!(pack_configuration(&[]).len() >= mem::size_of::<ListHeader>());
    }

    #[test]
    fn the_application_is_found_by_its_name() {
        let running = vec![(
            10u32,
            1u32,
            wide(r"\Device\HarddiskVolume2\Program Files\nodejs\node.exe"),
        )];
        let found = resolve_application("node.exe", &running).expect("node.exe is running");
        assert!(found.ends_with("node.exe"));
        assert!(resolve_application("nothing.exe", &running).is_none());
    }
}
