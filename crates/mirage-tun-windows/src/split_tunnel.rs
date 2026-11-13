//! The split-tunnel driver: an application that leaves the tunnel.
//!
//! The network bypass (`crate::bypass`) is a hole in the routing: it lets a
//! DESTINATION out of the tunnel.  This module is the other half -- it lets an
//! APPLICATION out, by image.
//!
//! The work is done by the split-tunnel driver of ours
//! (`mirage-split-tunnel.sys`): it watches the processes, and for the ones on
//! the list it keeps the traffic of the tunnel away from them.  The driver and
//! the user mode of ours speak one protocol, and it is the protocol of the
//! crate `mirage-split-tunnel`: our own commands, our own structures, our own
//! state machine.
//!
//! ```text
//! open the device  ->  GET_STATE  ->  RESET (if it is not Started)
//!                   ->  INITIALIZE (the two sublayers of the user mode)
//!                   ->  REGISTER_PROCESSES (the whole machine, once)
//!                   ->  REGISTER_IP_ADDRESSES (tunnel + internet)
//!                   ->  SET_CONFIGURATION (the images to exclude)
//!                   ->  DEQUEUE_EVENT (a thread, until the list is emptied)
//! ```
//!
//! The order matters: the driver is a state machine, and every request that
//! does not belong to the current state is refused.
//!
//! The fork of another driver is gone.  It spoke a protocol of its own --
//! another device, another numbers, another layout of the structures -- and
//! the driver of ours does not answer it.  So the two fallbacks of the old
//! code are gone with it: the device of the fork and the driver of Mullvad.
//! What is left is one driver, one protocol, and the crate that holds both
//! sides of it.

#![cfg(target_os = "windows")]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mirage_split_tunnel::error::Error as DriverError;
use mirage_split_tunnel::image;
use mirage_split_tunnel::process;
use mirage_split_tunnel::protocol::{EventKind, IpAddresses};
use mirage_split_tunnel::windows::agent::Agent;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// A failure of the split-tunnel path.
#[derive(Debug)]
pub enum SplitTunnelError {
    /// The driver is not there (not installed, or not started).
    DeviceUnavailable(String),
    /// The driver is held by another instance.
    ///
    /// The device of the driver is busy: while one instance of the tunnel
    /// holds it, the next one is told to go away.  That is not a failure --
    /// it is a queue.  The instance that holds it is shutting down, and the
    /// next one has to wait for it.
    DeviceBusy(u32),
    /// The driver refused a request.
    Driver(String, u32),
    /// The WFP layer refused.
    Wfp(String, u32),
    /// The list of applications could not be turned into paths.
    NoSuchApplication(String),
    /// Anything else the platform said.
    Platform(io::Error),
}

impl fmt::Display for SplitTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitTunnelError::DeviceUnavailable(m) => write!(f, "the split-tunnel device is not there: {m}"),
            SplitTunnelError::DeviceBusy(code) => {
                write!(f, "the split-tunnel device is held by another instance (error {code})")
            }
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

/// The agent of the driver, shared between the thread of the events and the
/// thread of the client.
///
/// The agent holds two handles of the kernel: the device of the driver and
/// the engine of the firewall.  Both are numbers that the kernel knows, both
/// are used from one thread at a time, and both the driver and the firewall
/// are thread safe.
struct SharedAgent(std::sync::Mutex<Agent>);

// SAFETY: the agent is behind a mutex, so the two threads never touch the
// handles at the same time; the handles themselves are numbers that the
// kernel and the firewall accept from any thread.
unsafe impl Send for SharedAgent {}
unsafe impl Sync for SharedAgent {}

impl SharedAgent {
    /// The agent, locked.
    fn lock(&self) -> std::sync::MutexGuard<'_, Agent> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The exclusion, live: the driver is engaged and the applications on the
/// list leave the tunnel.
pub struct SplitTunnel {
    /// The agent of the driver: the device, the rules of the user mode and
    /// the state between them.
    agent: Arc<SharedAgent>,
    /// The address the driver was told is the tunnel.
    tunnel: Ipv4Addr,
    /// The address the driver was told is the internet.
    internet: Ipv4Addr,
    /// The number of the interface that leads to the internet.
    internet_interface: u32,
    /// The names the person asked about: the log carries them and the rest
    /// of the machine is a debug line.
    watched: Arc<std::sync::Mutex<Vec<String>>>,
    /// The processes of the machine and the path of the image of each of
    /// them.  The driver says that a process has been born; the path of its
    /// image is only known here, in the user mode.
    processes: Arc<std::sync::Mutex<HashMap<u64, String>>>,
    /// The flag that tells the thread of the events to stop.
    stop: Arc<AtomicBool>,
    /// The thread of the events, and the way to know that it is over.
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

        // The driver matches an image by the path of it in the spelling of
        // the system: `C:\Windows\System32\node.exe`.  The names the person
        // typed have to be turned into such paths.
        //
        // EVERY running process that carries the wanted name is taken, not
        // just the first one: two different images may carry the same file
        // name ("node.exe" of Program Files and one of the cache of a
        // tool), and the first match is not enough -- the other one keeps
        // going through the tunnel, and the driver was given the wrong
        // image.
        //
        // A name that cannot be resolved is not a reason to give the whole
        // list up: the applications that ARE known still leave the tunnel.
        // A bare name ("node.exe") that is not running right now is looked
        // for on the disk -- the driver takes the images it is given and
        // excludes them when they show up, so a path that is known now is
        // enough.
        let running = running_images();
        let (excluded, missing) =
            resolve_applications(applications, &running, |file| image::find_on_disk(file));
        if excluded.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication(missing.join(", ")));
        }
        if !missing.is_empty() {
            tracing::info!(
                missing = %missing.join(", "),
                "split-tunnel: these names are neither running nor on the disk; the rest of the list leaves the tunnel"
            );
        }
        // The paths of the images, in the spelling the driver compares.
        let images = image::image_paths(&excluded);

        // The interface that leads to the internet: the driver rewrites the
        // sockets of the excluded applications onto it, so that they leave
        // the tunnel.  The user mode knows the interface; the driver only
        // has to be told.
        let internet_interface = internet_interface_for(internet);

        // The device comes FIRST, and the driver is put back into its fresh
        // state before anything else happens.
        //
        // This order is the whole point.  A driver that still holds the state
        // of an earlier client keeps that client's filters, and those filters
        // BIND the traffic of the machine to the interface that client named
        // as "the internet".  The traffic then leaves the machine natively
        // while the tunnel stands right there, and the routing table cannot
        // explain it: the FIB is identical in every session.  The state is
        // therefore cleared first.
        //
        // The driver is put back into its fresh state ONLY when it is not
        // fresh already: a reset tears the driver's firewall down and builds
        // it again -- the filters and the callouts are unregistered and
        // registered anew -- and the driver does not survive many of those.
        // A driver that is already fresh is left alone.
        let mut agent = Agent::open().map_err(map_error)?;
        let addresses = IpAddresses::v4_on(tunnel.octets(), internet.octets(), internet_interface);
        let state = match agent.engage(&images, addresses) {
            Ok(state) => state,
            Err(error) => {
                // The driver must not keep a state it was never fully given:
                // it is put back to the beginning, so that the next client
                // finds it fresh.
                let _ = agent.retract();
                return Err(map_error(error));
            }
        };

        // The book of the processes: the driver says that a process has been
        // born, and the user mode is the one that knows the path of its
        // image.  The table of the machine is read here, once.
        let processes: HashMap<u64, String> = running
            .iter()
            .map(|(id, path)| (*id, path.to_string_lossy().to_string()))
            .collect();

        // The events: the driver says who was born and who is gone.
        //
        // The driver tells about EVERY process on the machine, so the log
        // only carries the names the person asked about.  The names are
        // the ones that were ASKED for -- not the ones that happened to be
        // running: an application that is not running yet leaves the tunnel
        // when it starts, and the log has to say so.
        let watched = Arc::new(std::sync::Mutex::new(watched_names(applications)));
        let processes = Arc::new(std::sync::Mutex::new(processes));
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let shared = Arc::new(SharedAgent(std::sync::Mutex::new(agent)));
        let events = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let watched = Arc::clone(&watched);
            let processes = Arc::clone(&processes);
            thread::Builder::new()
                .name("mirage-split-tunnel".into())
                .spawn(move || {
                    event_loop(shared, stop, watched, processes);
                    let _ = done_tx.send(());
                })
                .ok()
        };

        tracing::info!(
            state = state.as_u32(),
            tunnel = %tunnel,
            internet = %internet,
            interface = internet_interface,
            applications = images.len(),
            "split-tunnel: the applications are out of the tunnel"
        );

        Ok(Self {
            agent: shared,
            tunnel,
            internet,
            internet_interface,
            watched,
            processes,
            stop,
            events: events.map(|handle| (done_rx, handle)),
        })
    }

    /// The tunnel carries another address -- the driver must know it.
    ///
    /// The box hands out one address per session, and the adapter takes the
    /// new one on the fly.  The driver decides by the addresses which traffic
    /// is "inside the tunnel": a driver that still carries the old address
    /// does not see the new tunnel at all, and the applications that are to
    /// leave the tunnel do not leave it.  They go into the tunnel instead, and
    /// the work of the machine slows down to the speed of the tunnel.
    pub fn retunnel(&mut self, tunnel: Ipv4Addr) -> Result<(), SplitTunnelError> {
        if tunnel == self.tunnel {
            return Ok(());
        }
        let addresses =
            IpAddresses::v4_on(tunnel.octets(), self.internet.octets(), self.internet_interface);
        self.agent.lock().retunnel(addresses).map_err(map_error)?;
        tracing::info!(
            from = %self.tunnel,
            to = %tunnel,
            "split-tunnel: the driver has the new tunnel address"
        );
        self.tunnel = tunnel;
        Ok(())
    }

    /// Replace the list of applications that leave the tunnel.
    pub fn set_exclusions(&mut self, applications: &[String]) -> Result<(), SplitTunnelError> {
        if applications.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication("the list is empty".into()));
        }
        let running = running_images();
        // The list that comes here carries the paths themselves (the ones
        // that were found on the disk), so the disk is not searched again.
        let (excluded, missing) =
            resolve_applications(applications, &running, |_| None);
        if excluded.is_empty() {
            return Err(SplitTunnelError::NoSuchApplication(missing.join(", ")));
        }
        let images = image::image_paths(&excluded);
        self.agent.lock().update_images(&images).map_err(map_error)?;
        // The names the log carries follow the list.
        if let Ok(mut watched) = self.watched.lock() {
            *watched = watched_names(applications);
        }
        Ok(())
    }

    /// The state the driver is in.
    ///
    /// The numbers are the ones of the driver of ours: 1 is the fresh state,
    /// 4 is the state of an engaged driver.  They are the same numbers the
    /// old driver used, so the window that shows the state does not change.
    pub fn state(&self) -> Result<u64, SplitTunnelError> {
        let state = self.agent.lock().state().map_err(map_error)?;
        Ok(state.as_u32() as u64)
    }
}

impl Drop for SplitTunnel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The list is emptied and the driver is put back to the beginning:
        // its answer is read.  A driver that cannot be reset is in the state
        // it calls ZOMBIE, and it says itself that from there it will not
        // be able to unload.  That must be loud -- the service of the driver
        // must not be stopped, the way the driver unloads ends in a bug
        // check when the reset fails.
        {
            let mut agent = self.agent.lock();
            if let Err(error) = agent.retract() {
                tracing::error!(
                    error = %error,
                    "split-tunnel: the driver did not come back to its fresh state - do NOT stop its service"
                );
            }
        }
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
    }
}

/// The error of the driver, in the shape the rest of the client knows.
fn map_error(error: DriverError) -> SplitTunnelError {
    match error {
        DriverError::Device { action, code } => {
            // 5 = ACCESS_DENIED, 32 = SHARING_VIOLATION: the device is there
            // and somebody else holds it.
            if code == 5 || code == 32 {
                SplitTunnelError::DeviceBusy(code)
            } else {
                SplitTunnelError::DeviceUnavailable(format!("{action} (error {code})"))
            }
        }
        DriverError::Command { command, code } => SplitTunnelError::Driver(
            format!("the command {command} of our protocol was refused"),
            code,
        ),
        DriverError::ServiceMissing { name } => {
            SplitTunnelError::DeviceUnavailable(format!("the service {name} is not on this machine"))
        }
        DriverError::Service { name, code } => {
            SplitTunnelError::Driver(format!("the service {name} refused"), code)
        }
        DriverError::Protocol(inner) => {
            SplitTunnelError::Driver(format!("the buffer of the driver: {inner}"), 0)
        }
        DriverError::Version { got, expected } => SplitTunnelError::Driver(
            format!("the driver speaks the version {got}, and we speak {expected}"),
            got,
        ),
        DriverError::State { got } => {
            SplitTunnelError::Driver(format!("the driver is in the state {got}"), got)
        }
        DriverError::Io(inner) => SplitTunnelError::Platform(inner),
        DriverError::Argument(text) => SplitTunnelError::Driver(text, 0),
    }
}

/// The change of the state of an application that leaves the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The application left the tunnel.
    Left,
    /// The application came back into the tunnel.
    CameBack,
}

/// The applications that are out of the tunnel, and the processes that hold
/// them there.
///
/// The driver tells about EVERY process of the machine, and it tells about
/// every process that starts and every process that stops: its events are
/// about the PROCESSES, not about the applications.  A machine that spawns
/// node.exe a hundred times an hour said "the application left the tunnel" a
/// hundred times and "the application came back into the tunnel" a hundred
/// times, while the application never left the tunnel at all -- it was
/// running the whole time, and the processes that came and went were its
/// children.
///
/// So the state is kept per image, and the instances are counted: an
/// application leaves the tunnel when its first instance leaves it, and it
/// comes back when its last instance comes back.  The same event twice
/// changes nothing: the instance is already known.
#[derive(Debug, Default)]
pub struct ExcludedState {
    /// The names the person asked about, in lower case.
    watched: Vec<String>,
    /// The instances that are out of the tunnel, per image.
    outside: HashMap<String, HashSet<u64>>,
}

impl ExcludedState {
    /// The state of the applications of the list.
    pub fn new(watched: Vec<String>) -> Self {
        let mut state = Self::default();
        state.set_watched(watched);
        state
    }

    /// The names the person asked about.
    pub fn watched(&self) -> &[String] {
        &self.watched
    }

    /// The list of the applications changed.
    ///
    /// The applications that are not on the list any more are not ours, and
    /// their instances are forgotten.  The ones that stay keep their
    /// instances: the driver did not change them either.
    pub fn set_watched(&mut self, watched: Vec<String>) {
        let mut wanted: Vec<String> = Vec::new();
        for name in watched {
            let name = name.trim().to_ascii_lowercase();
            if name.is_empty() || wanted.contains(&name) {
                continue;
            }
            wanted.push(name);
        }
        if wanted == self.watched {
            return;
        }
        self.watched = wanted;
        let watched = self.watched.clone();
        self.outside
            .retain(|image, _| watched.iter().any(|name| image.contains(name)));
    }

    /// Whether the image is one of the applications the person asked about.
    pub fn is_watched(&self, image: &str) -> bool {
        let image = image.to_ascii_lowercase();
        self.watched.iter().any(|name| image.contains(name))
    }

    /// A process of an application left the tunnel.
    ///
    /// The transition comes back only when the state really changed: the
    /// first instance of the image is the one that leaves the tunnel, and
    /// the instances that follow it are the same application leaving
    /// again.
    pub fn started(&mut self, image: &str, pid: u64) -> Option<Transition> {
        if !self.is_watched(image) {
            return None;
        }
        let key = image.to_ascii_lowercase();
        let instances = self.outside.entry(key).or_default();
        let first = instances.is_empty();
        instances.insert(pid);
        if first {
            Some(Transition::Left)
        } else {
            None
        }
    }

    /// A process of an application came back into the tunnel.
    ///
    /// The transition comes back only when the last instance of the image
    /// is gone: the application is still out of the tunnel as long as one
    /// of its processes is running.
    pub fn stopped(&mut self, image: &str, pid: u64) -> Option<Transition> {
        if !self.is_watched(image) {
            return None;
        }
        let key = image.to_ascii_lowercase();
        let Some(instances) = self.outside.get_mut(&key) else {
            return None;
        };
        instances.remove(&pid);
        if !instances.is_empty() {
            return None;
        }
        self.outside.remove(&key);
        Some(Transition::CameBack)
    }

    /// The applications that are out of the tunnel right now.
    pub fn outside(&self) -> Vec<String> {
        let mut out: Vec<String> = self.outside.keys().cloned().collect();
        out.sort();
        out
    }
}

/// The move of the book, given the event of the driver.
///
/// The events of the driver of ours are about the PROCESSES: one that was
/// born, and one that is gone.  The book of the applications counts the
/// instances of every image, so that an application leaves the tunnel once
/// and comes back once, however many processes of it there are.
fn apply_event(
    state: &mut ExcludedState,
    kind: EventKind,
    image: &str,
    process_id: u64,
) -> Option<Transition> {
    match kind {
        EventKind::ProcessStarted => state.started(image, process_id),
        EventKind::ProcessExited => state.stopped(image, process_id),
        EventKind::ConfigurationChanged => None,
    }
}

/// The events: who started and who stopped being out of the tunnel.
///
/// The driver of ours says that a PROCESS has been born or has died -- it
/// says nothing about the applications, and it does not say which image the
/// process has: the path of an image in the spelling of the system is only
/// known in the user mode.
///
/// So the thread of the events does three things with every event: it learns
/// the path of the image of the process that was born, it tells the driver
/// about it (the command REGISTER_PROCESS -- the driver cannot match a
/// process it has never been told about), and it moves the book of the
/// applications.
///
/// The events of the driver are about the PROCESSES, not about the
/// applications: every process that starts and every process that stops is an
/// event of its own.  A machine that spawns node.exe a hundred times an hour
/// said "the application left the tunnel" a hundred times and "the
/// application came back into the tunnel" a hundred times -- while the
/// application never left the tunnel at all: it was running the whole time,
/// and the processes that came and went were its children.
///
/// So the state is kept per image, and the instances are counted: an
/// application leaves the tunnel when its first instance leaves it, and it
/// comes back when its last instance comes back.
fn event_loop(
    agent: Arc<SharedAgent>,
    stop: Arc<AtomicBool>,
    watched: Arc<std::sync::Mutex<Vec<String>>>,
    processes: Arc<std::sync::Mutex<HashMap<u64, String>>>,
) {
    let mut state = ExcludedState::default();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let event = {
            let mut agent = agent.lock();
            match agent.next_event() {
                Ok(Some(event)) => Some(event),
                Ok(None) => None,
                Err(error) => {
                    if !is_empty_queue(&error) {
                        tracing::debug!(error = %error, "split-tunnel: the event request failed, retrying");
                    }
                    None
                }
            }
        };
        let Some(event) = event else {
            // The queue of the driver of ours is empty most of the time: it
            // does not wait for an event, it says that there is none.
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let Some(kind) = EventKind::from_u32(event.kind) else {
            tracing::debug!(kind = event.kind, "split-tunnel: an event from the driver that we do not know");
            continue;
        };
        let process_id = event.process_id;

        // The path of the image of the process: the book of the processes
        // knows it, and the system is asked when it does not.
        let image = match kind {
            EventKind::ProcessStarted => {
                let known = lock_map(&processes).get(&process_id).cloned();
                match known {
                    Some(image) => Some(image),
                    None => {
                        let found = image_path_of(process_id);
                        if let Some(image) = found.as_ref() {
                            lock_map(&processes).insert(process_id, image.clone());
                        }
                        found
                    }
                }
            }
            EventKind::ProcessExited => {
                // The process is gone: the book of the processes forgets it.
                let mut book = lock_map(&processes);
                book.remove(&process_id)
            }
            EventKind::ConfigurationChanged => None,
        };
        let Some(image) = image else {
            // The process is already gone, or there is nothing to say about
            // it: there is nothing to move.
            continue;
        };

        if kind == EventKind::ProcessStarted {
            // The driver does not know the path of the image: only the user
            // mode can read it, and the driver needs it to know which
            // applications leave the tunnel.
            let mut agent = agent.lock();
            if let Err(error) = agent.register_process(process_id, &image) {
                tracing::debug!(error = %error, process_id, "split-tunnel: the driver did not take the new process");
            }
        }

        // The names the log carries follow the list of the driver.
        let names = match watched.lock() {
            Ok(watched) => watched.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        state.set_watched(names);

        match apply_event(&mut state, kind, &image, process_id) {
            Some(Transition::Left) => {
                tracing::info!(application = %image, "split-tunnel: the application left the tunnel");
            }
            Some(Transition::CameBack) => {
                tracing::info!(application = %image, "split-tunnel: the application came back into the tunnel");
            }
            None => {
                tracing::debug!(
                    application = %image,
                    event = kind.as_u32(),
                    "split-tunnel: the state of the application did not change"
                );
            }
        }
    }
}

/// Whether the answer of the driver means "the queue is empty".
///
/// The driver of ours answers `STATUS_NOT_FOUND` when there is no event to
/// take.  Windows gives that as the code 1168 (`ERROR_NOT_FOUND`), and on
/// some builds as the code 2 (`ERROR_FILE_NOT_FOUND`).  Both mean the same
/// thing here: there is nothing in the queue.
fn is_empty_queue(error: &DriverError) -> bool {
    match error {
        DriverError::Command { code, .. } => *code == 1168 || *code == 2,
        _ => false,
    }
}

/// The book of the processes, locked.
fn lock_map(map: &std::sync::Mutex<HashMap<u64, String>>) -> std::sync::MutexGuard<'_, HashMap<u64, String>> {
    map.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The processes of the machine, with the path of their images.
fn running_images() -> Vec<(u64, PathBuf)> {
    process::running()
        .into_iter()
        .filter_map(|entry| entry.image.map(|image| (entry.id, image)))
        .collect()
}

/// The path of the image of a process, the way the system writes it.
///
/// The crate of ours reads the whole table of the machine at once; a single
/// process is asked here, because the driver says that one process has been
/// born and the answer of the system is wanted before anything else is done
/// with it.
fn image_path_of(process_id: u64) -> Option<String> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id as u32,
        )
    };
    if handle.is_null() {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..size as usize]))
}

/// The images of the applications the person named, and the names that could
/// not be found at all.
///
/// EVERY running process that carries the name is taken -- two different
/// images may carry the same file name, and the one that is left out keeps
/// going through the tunnel.  A bare name that is not running right now is
/// looked for on the disk: the driver takes the images it is given and
/// excludes them when they show up, so a path that is known at the moment
/// the driver is engaged is enough.
///
/// `from_disk` is given the file name of the wanted application and answers
/// the path of it, or nothing when the name is nowhere to be found.
fn resolve_applications<F>(
    applications: &[String],
    running: &[(u64, PathBuf)],
    mut from_disk: F,
) -> (Vec<PathBuf>, Vec<String>)
where
    F: FnMut(&str) -> Option<PathBuf>,
{
    let mut excluded: Vec<PathBuf> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for wanted in applications {
        let wanted = wanted.trim();
        if wanted.is_empty() {
            continue;
        }
        if image::is_bare_name(wanted) {
            // A bare name: EVERY image with that file name is taken.
            match image::resolve(wanted, running, false) {
                image::Resolution::Found(path) => {
                    let file = image::file_name_of(&path);
                    for (_, candidate) in running {
                        if image::file_name_of(candidate).eq_ignore_ascii_case(&file) {
                            push_path(&mut excluded, candidate.clone());
                        }
                    }
                }
                image::Resolution::NotFound(_) => {
                    // Not running: looked for on the disk.
                    match from_disk(wanted) {
                        Some(path) => push_path(&mut excluded, path),
                        None => missing.push(wanted.to_owned()),
                    }
                }
                image::Resolution::Exact(path) => push_path(&mut excluded, path),
            }
            continue;
        }
        // A path the person wrote.  It is honoured as it is: the drive alone
        // says which volume it is on, and the file does not have to be
        // running for that.
        match image::resolve(wanted, running, false) {
            image::Resolution::Exact(path) => {
                if has_volume(&path) {
                    push_path(&mut excluded, path);
                } else {
                    // A path without the letter of the volume is of no use to
                    // the driver: the identity of an application always
                    // carries the volume.
                    missing.push(wanted.to_owned());
                }
            }
            image::Resolution::Found(path) => push_path(&mut excluded, path),
            image::Resolution::NotFound(_) => missing.push(wanted.to_owned()),
        }
    }

    (excluded, missing)
}

/// Whether the path carries the letter of the volume.
///
/// `C:\Windows\node.exe` does, `Windows\node.exe` does not.  The driver
/// compares the path of an image in the spelling of the system, and that
/// spelling always carries the volume.
fn has_volume(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    (bytes.len() >= 2 && bytes[1] == b':') || text.starts_with("\\\\")
}

/// Add a path to the list, unless it is already there.
fn push_path(list: &mut Vec<PathBuf>, path: PathBuf) {
    let text = path.to_string_lossy();
    if list
        .iter()
        .any(|seen| seen.to_string_lossy().eq_ignore_ascii_case(&text))
    {
        return;
    }
    list.push(path);
}

/// The names the person asked about: the log carries them, the rest of the
/// machine is a debug line.
fn watched_names(applications: &[String]) -> Vec<String> {
    applications
        .iter()
        .filter_map(|app| {
            let file = file_name_of(app.trim());
            if file.is_empty() {
                None
            } else {
                Some(file.to_ascii_lowercase())
            }
        })
        .collect()
}

/// The file name of a path, the way the person wrote it.
fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The number of the interface that carries the address of the internet.
///
/// The driver of ours rewrites the sockets of the excluded applications onto
/// this interface, so that they leave the tunnel.  The user mode knows the
/// interface; the driver only has to be told.  Zero means that the interface
/// is not known.
fn internet_interface_for(address: Ipv4Addr) -> u32 {
    let wanted = u32::from_be_bytes(address.octets());
    let mut size: u32 = 0;
    // The first call asks how much the table of the adapters needs.
    unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return 0;
    }
    let mut buffer = vec![0u8; size as usize];
    let code = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            0,
            std::ptr::null(),
            buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if code != 0 {
        return 0;
    }
    let mut adapter = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        let mut unicast = unsafe { (*adapter).FirstUnicastAddress };
        while !unicast.is_null() {
            let sockaddr = unsafe { (*unicast).Address.lpSockaddr as *const SOCKADDR_IN };
            if !sockaddr.is_null() {
                let raw = unsafe { (*sockaddr).sin_addr.S_un.S_addr };
                if u32::from_be(raw) == wanted {
                    return unsafe { (*adapter).Anonymous1.Anonymous.IfIndex };
                }
            }
            unicast = unsafe { (*unicast).Next };
        }
        adapter = unsafe { (*adapter).Next };
    }
    0
}

/// The path of the application the person named, the way the system writes
/// it.
///
/// The driver of ours takes the path of the image in the spelling of the
/// system, and the switch that keeps the tunnel honest takes the same path.
/// Both come from the same place: the running processes, and then the disk --
/// an application that is not running now must be excluded all the same, or
/// it goes into the tunnel the moment it starts.
pub fn application_paths(applications: &[String]) -> Vec<String> {
    let running = running_images();
    let mut paths: Vec<PathBuf> = Vec::new();
    for wanted in applications {
        let wanted = wanted.trim();
        if wanted.is_empty() {
            continue;
        }
        // A full path the person wrote.
        if !image::is_bare_name(wanted) {
            let path = PathBuf::from(wanted);
            if path.is_file() {
                push_path(&mut paths, path);
            }
            continue;
        }
        // EVERY image with that file name is taken: two of them may carry
        // the same name ("node.exe" of Program Files and one of the cache
        // of a tool), and the one that is left out keeps going through the
        // tunnel.
        for (_, candidate) in &running {
            if image::file_name_of(candidate).eq_ignore_ascii_case(wanted) {
                push_path(&mut paths, candidate.clone());
            }
        }
    }
    image::image_paths(&paths)
}

/// The applications that are not running now, looked for on the disk.
///
/// The search is slow -- the disk is big -- so it does not belong on the way
/// the device comes up: a device that is slow to start is a device that is
/// killed before it carries.  The caller runs it in the background.
pub fn application_paths_on_disk(applications: &[String]) -> Vec<String> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for wanted in applications {
        let wanted = wanted.trim();
        if wanted.is_empty() {
            continue;
        }
        if !image::is_bare_name(wanted) {
            continue;
        }
        if let Some(path) = image::find_on_disk(wanted) {
            push_path(&mut paths, path);
        }
    }
    image::image_paths(&paths)
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

    /// The path of an image, the way the system writes it.
    fn image_path(text: &str) -> PathBuf {
        PathBuf::from(text)
    }

    #[test]
    fn the_application_is_found_by_its_name() {
        let running = vec![(10u64, image_path(r"C:\Program Files\nodejs\node.exe"))];
        let (excluded, missing) = resolve_applications(&["node.exe".to_owned()], &running, |_| None);
        assert!(missing.is_empty());
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].ends_with("node.exe"));
    }

    /// Two different images may carry the same file name -- and both of
    /// them have to leave the tunnel.  The first match is not enough: the
    /// other one keeps going through the tunnel.
    #[test]
    fn every_image_with_the_wanted_file_name_is_taken() {
        let running = vec![
            (
                10u64,
                image_path(r"C:\Program Files\nodejs\node.exe"),
            ),
            (20u64, image_path(r"D:\codex\node.exe")),
            (
                30u64,
                image_path(r"C:\Windows\System32\svchost.exe"),
            ),
        ];
        let (excluded, missing) = resolve_applications(&["node.exe".to_owned()], &running, |_| None);
        assert!(missing.is_empty());
        assert_eq!(excluded.len(), 2, "both images of node.exe are taken");
        assert!(excluded[0].to_string_lossy().contains("Program Files"));
        assert!(excluded[1].to_string_lossy().contains("codex"));
    }

    /// A name that is on the disk but not running is taken from the disk:
    /// the driver excludes the images it is given when they show up, so the
    /// path has to be known when the driver is engaged.
    #[test]
    fn a_name_that_is_on_the_disk_but_not_running_is_taken_from_the_disk() {
        let running = vec![(10u64, image_path(r"C:\Program Files\nodejs\node.exe"))];
        let applications = vec!["node.exe".to_owned(), "yandexbrowser.exe".to_owned()];
        let (excluded, missing) = resolve_applications(&applications, &running, |file| {
            if file.eq_ignore_ascii_case("yandexbrowser.exe") {
                Some(image_path(r"C:\Yandex\YandexBrowser.exe"))
            } else {
                None
            }
        });
        assert!(missing.is_empty(), "the name was found on the disk");
        assert_eq!(excluded.len(), 2, "the running image and the one on the disk");
        let texts: Vec<String> = excluded
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect();
        assert!(texts.iter().any(|text| text.contains("nodejs")));
        assert!(texts.iter().any(|text| text.contains("YandexBrowser.exe")));
    }

    /// A name that is neither running nor on the disk is reported -- and it
    /// does not keep the rest of the list from leaving the tunnel.
    #[test]
    fn a_name_that_is_nowhere_is_reported() {
        let running = vec![(10u64, image_path(r"C:\Program Files\nodejs\node.exe"))];
        let applications = vec!["node.exe".to_owned(), "nowhere.exe".to_owned()];
        let (excluded, missing) = resolve_applications(&applications, &running, |_| None);
        assert_eq!(excluded.len(), 1);
        assert_eq!(missing, vec!["nowhere.exe".to_owned()]);
    }

    /// A full path the person wrote is honoured as it is: the file does not
    /// have to be running.
    #[test]
    fn a_full_path_is_honoured_as_it_is() {
        let running: Vec<(u64, PathBuf)> = Vec::new();
        let (excluded, missing) =
            resolve_applications(&[r"E:\MU\main.exe".to_owned()], &running, |_| None);
        assert!(missing.is_empty());
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0], image_path(r"E:\MU\main.exe"));
    }

    /// The log carries the names that were ASKED for -- not the ones that
    /// happened to be running.
    #[test]
    fn the_watched_names_are_the_ones_that_were_asked_for() {
        let watched = watched_names(&[
            "node.exe".to_owned(),
            "C:\\Program Files\\nodejs\\node.exe".to_owned(),
            "YandexBrowser.exe".to_owned(),
        ]);
        assert_eq!(watched, vec!["node.exe".to_owned(), "node.exe".to_owned(), "yandexbrowser.exe".to_owned()]);
    }

    /// The image of the application the log kept talking about.
    const NODE: &str = r"c:\program files\nodejs\node.exe";

    /// An application leaves the tunnel once, no matter how many processes
    /// of it are running.
    #[test]
    fn an_application_leaves_the_tunnel_once() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(state.started(NODE, 42), Some(Transition::Left));
        // The child of the application leaves the tunnel as well, and the
        // application did not leave it a second time.
        assert_eq!(state.started(NODE, 43), None);
        assert_eq!(state.outside(), vec![NODE.to_owned()]);
    }

    /// An application that exits comes back exactly once.
    #[test]
    fn an_application_that_exits_comes_back_exactly_once() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(state.started(NODE, 42), Some(Transition::Left));
        assert_eq!(state.stopped(NODE, 42), Some(Transition::CameBack));
        // The same event again: nothing comes back a second time.
        assert_eq!(state.stopped(NODE, 42), None);
        assert!(state.outside().is_empty());
    }

    /// The children of an application do not toggle it: the application is
    /// still out of the tunnel while one of its processes is running.
    #[test]
    fn the_children_of_an_application_do_not_toggle_it() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(state.started(NODE, 42), Some(Transition::Left));
        assert_eq!(state.started(NODE, 43), None);
        assert_eq!(state.stopped(NODE, 43), None);
        assert_eq!(state.outside(), vec![NODE.to_owned()]);
        // The application itself is gone: now it comes back.
        assert_eq!(state.stopped(NODE, 42), Some(Transition::CameBack));
        assert!(state.outside().is_empty());
    }

    /// The same event twice does not move the state: the configuration of
    /// the applications is the same, and the state does not flip.
    #[test]
    fn the_same_event_twice_does_not_move_the_state() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(state.started(NODE, 42), Some(Transition::Left));
        let configuration = state.outside();
        assert_eq!(state.started(NODE, 42), None);
        assert_eq!(state.outside(), configuration);
        assert_eq!(state.stopped(NODE, 42), Some(Transition::CameBack));
        let configuration = state.outside();
        assert_eq!(state.stopped(NODE, 42), None);
        assert_eq!(state.outside(), configuration);
    }

    /// The applications of the machine that were not asked about are not
    /// ours: they move nothing.
    #[test]
    fn an_application_that_was_not_asked_about_moves_nothing() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        let other = r"c:\windows\system32\notepad.exe";
        assert_eq!(state.started(other, 7), None);
        assert_eq!(state.stopped(other, 7), None);
        assert!(state.outside().is_empty());
    }

    /// The list of the applications changed: the ones that are not on it
    /// any more are forgotten, and the ones that stay keep their state.
    #[test]
    fn a_changed_list_keeps_the_applications_that_stay() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(state.started(NODE, 42), Some(Transition::Left));
        state.set_watched(vec!["node.exe".to_owned(), "notepad.exe".to_owned()]);
        assert_eq!(state.outside(), vec![NODE.to_owned()]);
        state.set_watched(vec!["notepad.exe".to_owned()]);
        assert!(state.outside().is_empty());
        assert_eq!(state.stopped(NODE, 42), None);
    }

    /// The event of the driver that a process was born moves the book: the
    /// application leaves the tunnel.
    #[test]
    fn the_event_of_a_process_that_was_born_moves_the_book() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(
            apply_event(&mut state, EventKind::ProcessStarted, NODE, 42),
            Some(Transition::Left)
        );
        // A second process of the same image does not move it again.
        assert_eq!(
            apply_event(&mut state, EventKind::ProcessStarted, NODE, 43),
            None
        );
    }

    /// The event of the driver that a process is gone moves the book: the
    /// application comes back when its last process is gone.
    #[test]
    fn the_event_of_a_process_that_is_gone_moves_the_book() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        apply_event(&mut state, EventKind::ProcessStarted, NODE, 42);
        apply_event(&mut state, EventKind::ProcessStarted, NODE, 43);
        // One of the two is gone: the application is still out.
        assert_eq!(
            apply_event(&mut state, EventKind::ProcessExited, NODE, 43),
            None
        );
        // The last one is gone: now it comes back.
        assert_eq!(
            apply_event(&mut state, EventKind::ProcessExited, NODE, 42),
            Some(Transition::CameBack)
        );
    }

    /// The event of the driver that the list has changed moves nothing: the
    /// list itself is not an application.
    #[test]
    fn the_event_of_a_changed_list_moves_nothing() {
        let mut state = ExcludedState::new(vec!["node.exe".to_owned()]);
        assert_eq!(
            apply_event(&mut state, EventKind::ConfigurationChanged, NODE, 42),
            None
        );
        assert!(state.outside().is_empty());
    }
}
