use std::ffi::c_void;

use tokio::sync::mpsc;

use crate::error::IosTunError;

// ── Write callback ────────────────────────────────────────────────────────────

/// C function pointer type Swift provides for Rust to send outbound packets.
///
/// Swift writes the returned bytes into `packetFlow.writePackets(_:withProtocols:)`.
/// The callback is guaranteed to be valid for the lifetime of `TunContext`.
pub type WriteFn = extern "C" fn(*const u8, usize, *mut c_void);

/// Wrapper around the Swift-provided write callback.
///
/// # Safety
///
/// `fn_ptr` and `ctx` are pointers obtained from Swift (C FFI). The caller
/// guarantees they remain valid for the lifetime of this struct. The struct
/// is `Send` because the Network Extension serialises calls from a single
/// dispatch queue, and the function pointer itself has no thread affinity
/// restrictions at the C ABI level.
pub struct WriteCallback {
    fn_ptr: WriteFn,
    ctx: *mut c_void,
}

// SAFETY: Swift NEPacketTunnelProvider is single-threaded by default (runs on
// a private serial queue). The fn_ptr is a stateless C function. The ctx
// pointer is used only via the fn_ptr, which Swift guarantees is safe to call
// from any thread while the extension is alive.
unsafe impl Send for WriteCallback {}
unsafe impl Sync for WriteCallback {}

impl WriteCallback {
    /// Construct from raw FFI parameters.
    ///
    /// # Safety
    ///
    /// `fn_ptr` must be a valid C function pointer. `ctx` must remain valid
    /// until this struct is dropped.
    pub unsafe fn new(fn_ptr: WriteFn, ctx: *mut c_void) -> Self {
        Self { fn_ptr, ctx }
    }

    /// Invoke the callback, sending `data` to Swift.
    pub fn send(&self, data: &[u8]) {
        (self.fn_ptr)(data.as_ptr(), data.len(), self.ctx);
    }
}

// ── IosTunDevice ──────────────────────────────────────────────────────────────

/// Channel-based TUN device for iOS.
///
/// - Inbound (Swift → Rust): Swift calls `mirage_tun_process_packet` which
///   sends data through `inbound_tx`. The stack reads from `inbound_rx`.
/// - Outbound (Rust → Swift): The stack sends processed packets via
///   `outbound_tx`. The pump task receives them and invokes `write_cb`.
pub struct IosTunDevice {
    /// Name of this virtual interface (informational only on iOS).
    name: String,
    /// Receives raw IP packets coming from the device (via Swift packetFlow).
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Sends raw IP packets destined for the device (to Swift packetFlow).
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
}

impl IosTunDevice {
    /// Channel capacity for packet queues.
    ///
    /// Keep small to stay within the 15 MB iOS Network Extension budget.
    const CHANNEL_CAPACITY: usize = 64;

    /// Build paired device + channel endpoints.
    ///
    /// Returns:
    /// - `IosTunDevice` — held by the stack runner
    /// - `inbound_tx` — fed by `mirage_tun_process_packet` FFI
    /// - `outbound_rx` — drained by the outbound pump task
    pub fn new(name: impl Into<String>) -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (inbound_tx, inbound_rx) = mpsc::channel(Self::CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::channel(Self::CHANNEL_CAPACITY);
        let device = Self {
            name: name.into(),
            inbound_rx,
            outbound_tx,
        };
        (device, inbound_tx, outbound_rx)
    }

    /// Interface name (informational — NE assigns the real `utun*` name in Swift).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Decompose into raw channels for use with stack pump loops.
    ///
    /// Mirrors `WintunDevice::take_channels()` on Windows.
    pub fn take_channels(
        self,
    ) -> (
        mpsc::Receiver<Vec<u8>>, // inbound: stack reads from here
        mpsc::Sender<Vec<u8>>,   // outbound: stack writes here
    ) {
        (self.inbound_rx, self.outbound_tx)
    }
}

// ── configure / close no-ops ──────────────────────────────────────────────────

impl IosTunDevice {
    /// No-op: iOS Network Extension configures the interface via
    /// `setTunnelNetworkSettings(_:completionHandler:)` in Swift.
    pub fn configure_noop(&self) -> Result<(), IosTunError> {
        Ok(())
    }

    /// No-op: NE lifecycle teardown is managed by Swift.
    pub fn close_noop(self) -> Result<(), IosTunError> {
        Ok(())
    }
}
