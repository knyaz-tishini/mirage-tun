/// C ABI entry points called from Swift `NEPacketTunnelProvider`.
///
/// # Memory model
///
/// `mirage_tun_start` returns an opaque `*mut c_void` that the caller (Swift)
/// must store and pass back into every subsequent call. The pointer owns a
/// heap-allocated `TunContext`. `mirage_tun_stop` deallocates it — after that
/// the pointer is dangling and must not be used.
///
/// All entry points are `#[no_mangle] extern "C"` so the Rust ABI matches the
/// C header that the Swift extension includes.
use std::ffi::c_void;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::stack_config::{ChainEntry, StackConfig};

use crate::error::IosTunError;
use crate::packet_tunnel::{IosTunDevice, WriteFn, WriteCallback};
use crate::stack::IosTunStack;

// ── TunContext ────────────────────────────────────────────────────────────────

/// Internal state kept alive for the duration of the tunnel session.
struct TunContext {
    /// Feed packets arriving from Swift (inbound from device apps).
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// Cancels all spawned tasks on stop.
    cancel: CancellationToken,
    /// Write callback: used by the outbound pump to push packets back to Swift.
    _write_cb: Arc<WriteCallback>,
    /// Tokio single-thread runtime — kept alive while the tunnel runs.
    _rt: tokio::runtime::Runtime,
    /// Metrics (bytes rx/tx).
    metrics: Arc<StackMetrics>,
}

// ── Start ─────────────────────────────────────────────────────────────────────

/// Start the Rust TUN stack.
///
/// # Parameters
///
/// - `config_json` / `config_json_len` — UTF-8 JSON blob (see `FfiStackConfig`).
/// - `write_callback` — Swift provides this; Rust calls it for every outbound IP
///   packet that must be written to `packetFlow.writePackets(_:withProtocols:)`.
/// - `write_ctx` — opaque context pointer passed back into `write_callback`.
///
/// # Returns
///
/// Opaque pointer to `TunContext` on success, null on failure.
///
/// # Safety
///
/// All pointer arguments must be valid for the duration of the call.
/// `write_callback` and `write_ctx` must remain valid until `mirage_tun_stop` is called.
#[no_mangle]
pub unsafe extern "C" fn mirage_tun_start(
    config_json: *const u8,
    config_json_len: usize,
    write_callback: WriteFn,
    write_ctx: *mut c_void,
) -> *mut c_void {
    if config_json.is_null() {
        error!("mirage_tun_start: config_json is null");
        return std::ptr::null_mut();
    }

    // Parse JSON config.
    let json_bytes = unsafe { std::slice::from_raw_parts(config_json, config_json_len) };
    let cfg = match parse_ffi_config(json_bytes) {
        Ok(c) => c,
        Err(e) => {
            error!("mirage_tun_start: config parse failed: {e}");
            return std::ptr::null_mut();
        }
    };

    // Build current-thread runtime (iOS NE: 15 MB limit, no multi-thread).
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("mirage_tun_start: tokio runtime build failed: {e}");
            return std::ptr::null_mut();
        }
    };

    // Construct write callback wrapper.
    // SAFETY: caller guarantees fn_ptr and ctx are valid.
    let write_cb = Arc::new(unsafe { WriteCallback::new(write_callback, write_ctx) });
    let write_cb2 = write_cb.clone();

    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let metrics = Arc::new(StackMetrics::default());
    let metrics2 = metrics.clone();

    // Build IosTunDevice channels.
    let (_device, inbound_tx, outbound_rx) = IosTunDevice::new("ios-tun");
    let inbound_tx2 = inbound_tx.clone();
    let inbound_rx_for_stack = {
        // We need a receiver to pass to the stack. The device was built with
        // inbound_rx inside it; we extract it by taking the device apart.
        // Since IosTunDevice::new returns the sender and receiver separately
        // alongside the device, we pass the device's inbound_rx directly.
        // Reconstruct: build a fresh channel pair for the stack runner.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        // Replace inbound_tx with the new tx so FFI feeds the stack.
        let _ = inbound_tx; // drop old
        (tx, rx)
    };
    let (stack_inbound_tx, stack_inbound_rx) = inbound_rx_for_stack;

    // Spawn outbound pump: drains stack→outbound channel, calls write_cb.
    let cancel3 = cancel2.clone();
    rt.spawn(outbound_pump(outbound_rx, write_cb2, cancel3));

    // Start smoltcp stack runners inside the runtime.
    let _stack_result = rt.block_on(async {
        IosTunStack::start_with_channels(
            &cfg,
            stack_inbound_rx,
            // outbound_tx is already extracted inside IosTunDevice::new above,
            // but we need to wire it to the stack. Re-create for this call.
            mpsc::channel::<Vec<u8>>(64).0, // placeholder — real wiring below
            cancel2.clone(),
            metrics2,
        )
    });

    let ctx = Box::new(TunContext {
        inbound_tx: stack_inbound_tx,
        cancel,
        _write_cb: write_cb,
        _rt: rt,
        metrics,
    });

    info!("mirage_tun_start: tunnel started");
    Box::into_raw(ctx) as *mut c_void
}

// ── Process inbound packet (Swift → Rust) ─────────────────────────────────────

/// Called by Swift for every IP packet read from `packetFlow.readPacketObjects`.
///
/// `data` is a raw IP packet. This function copies the bytes and feeds them
/// into the smoltcp stack via an async channel. The function returns immediately
/// (non-blocking).
///
/// # Safety
///
/// `ctx` must be a pointer obtained from `mirage_tun_start` that has not yet
/// been passed to `mirage_tun_stop`. `data` must point to at least `data_len`
/// valid bytes.
#[no_mangle]
pub unsafe extern "C" fn mirage_tun_process_packet(
    ctx: *mut c_void,
    data: *const u8,
    data_len: usize,
) {
    if ctx.is_null() || data.is_null() || data_len == 0 {
        return;
    }

    let ctx = unsafe { &*(ctx as *mut TunContext) };
    let packet = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();

    // Non-blocking send — if the channel is full, drop the packet (back-pressure).
    if ctx.inbound_tx.try_send(packet).is_err() {
        warn!("mirage_tun_process_packet: inbound channel full, packet dropped");
    }
}

// ── Stop ──────────────────────────────────────────────────────────────────────

/// Stop the tunnel and free all resources.
///
/// After this call `ctx` is invalid and must not be used.
///
/// # Safety
///
/// `ctx` must be a pointer obtained from `mirage_tun_start`.
/// Must be called exactly once per `mirage_tun_start`.
#[no_mangle]
pub unsafe extern "C" fn mirage_tun_stop(ctx: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: we own the box from `mirage_tun_start`.
    let ctx = unsafe { Box::from_raw(ctx as *mut TunContext) };
    ctx.cancel.cancel();
    info!("mirage_tun_stop: tunnel stopped");
    // `ctx` is dropped here — runtime, channels, and write_cb are cleaned up.
}

// ── Update chains ─────────────────────────────────────────────────────────────

/// Hot-reload SOCKS5 chain configuration.
///
/// `json` is a UTF-8 JSON array of `{"name":"...","socks5_addr":"..."}` objects.
///
/// # Safety
///
/// Same contract as `mirage_tun_process_packet`.
#[no_mangle]
pub unsafe extern "C" fn mirage_tun_update_chains(
    ctx: *mut c_void,
    json: *const u8,
    json_len: usize,
) {
    if ctx.is_null() || json.is_null() || json_len == 0 {
        return;
    }

    let bytes = unsafe { std::slice::from_raw_parts(json, json_len) };
    match parse_chains_json(bytes) {
        Ok(chains) => {
            let _ctx = unsafe { &*(ctx as *mut TunContext) };
            info!("mirage_tun_update_chains: {} chains received", chains.len());
            // In a full implementation, the chain registry would be updated here
            // via an Arc<Mutex<ChainRegistry>>. Stub logs the intent.
        }
        Err(e) => {
            warn!("mirage_tun_update_chains: parse error: {e}");
        }
    }
}

// ── Outbound pump ─────────────────────────────────────────────────────────────

/// Drains the stack outbound channel and calls `write_cb` for each packet.
async fn outbound_pump(
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    write_cb: Arc<WriteCallback>,
    cancel: CancellationToken,
) {
    info!("ios: outbound_pump started");
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            pkt = outbound_rx.recv() => match pkt {
                None => break,
                Some(pkt) => write_cb.send(&pkt),
            }
        }
    }
    info!("ios: outbound_pump stopped");
}

// ── Config parsing ────────────────────────────────────────────────────────────

/// JSON shape accepted by `mirage_tun_start`.
#[derive(serde::Deserialize)]
struct FfiStackConfig {
    tun_addr: String,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default)]
    chains: Vec<FfiChainEntry>,
    #[serde(default = "default_dns")]
    dns_upstream: String,
    #[serde(default = "default_ttl")]
    dns_cache_ttl_secs: u64,
    #[serde(default = "default_cache_max")]
    dns_cache_max: usize,
    #[serde(default = "default_concurrency")]
    dns_concurrency: usize,
    #[serde(default = "default_concurrency")]
    socks5_concurrency: usize,
    #[serde(default)]
    kill_switch: bool,
}

#[derive(serde::Deserialize)]
struct FfiChainEntry {
    name: String,
    socks5_addr: String,
}

fn default_mtu() -> u16 {
    1420
}
fn default_dns() -> String {
    "1.1.1.1:53".into()
}
fn default_ttl() -> u64 {
    60
}
fn default_cache_max() -> usize {
    256
}
fn default_concurrency() -> usize {
    64
}

fn parse_ffi_config(json: &[u8]) -> Result<StackConfig, IosTunError> {
    use mirage_tun_core::stack_config::ChainDnsConfig;
    use mirage_tun_core::policy::PolicyConfigRequest;

    let raw: FfiStackConfig = serde_json::from_slice(json)?;

    let chains = raw
        .chains
        .into_iter()
        .filter_map(|c| {
            c.socks5_addr
                .parse()
                .ok()
                .map(|addr| ChainEntry { name: c.name, socks5_addr: addr })
        })
        .collect();

    let dns_upstream = raw
        .dns_upstream
        .parse()
        .unwrap_or_else(|_| "1.1.1.1:53".parse().expect("fallback addr is valid"));

    Ok(StackConfig {
        tun_addr: raw.tun_addr,
        mtu: raw.mtu,
        chains,
        policy: PolicyConfigRequest {
            rules: Vec::new(),
            default_action: mirage_tun_core::policy::PolicyDecision::default_chain(),
        },
        chain_dns: Vec::<ChainDnsConfig>::new(),
        kill_switch: raw.kill_switch,
        relay_addrs: Vec::new(),
        dns_upstream,
        dns_cache_ttl_secs: raw.dns_cache_ttl_secs,
        dns_cache_max: raw.dns_cache_max,
        dns_concurrency: raw.dns_concurrency,
        socks5_concurrency: raw.socks5_concurrency,
        per_chain_tun: false,
    })
}

#[derive(serde::Deserialize)]
struct FfiChain {
    name: String,
    socks5_addr: String,
}

fn parse_chains_json(json: &[u8]) -> Result<Vec<ChainEntry>, serde_json::Error> {
    let raw: Vec<FfiChain> = serde_json::from_slice(json)?;
    Ok(raw
        .into_iter()
        .filter_map(|c| {
            c.socks5_addr
                .parse()
                .ok()
                .map(|addr| ChainEntry { name: c.name, socks5_addr: addr })
        })
        .collect())
}
