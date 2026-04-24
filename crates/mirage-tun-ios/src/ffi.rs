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

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use mirage_tun_core::chains::{ChainConfig, ChainRegistry};
use mirage_tun_core::metrics::StackMetrics;
use mirage_tun_core::stack_config::{ChainEntry, StackConfig};
use mirage_tun_core::traits::TunStack;

use crate::error::IosTunError;
use crate::packet_tunnel::{WriteFn, WriteCallback};
use crate::stack::{clone_inbound_tx, IosTunStack};

// ── TunContext ────────────────────────────────────────────────────────────────

/// Internal state kept alive for the duration of the tunnel session.
struct TunContext {
    /// Cancels all spawned tasks on stop.
    cancel: CancellationToken,
    /// Write callback — kept alive so the outbound pump's Arc<WriteCallback>
    /// remains valid for the tunnel lifetime.
    _write_cb: Arc<WriteCallback>,
    /// Hot-reloadable chain registry — shared with stack tasks.
    chain_registry: Arc<ChainRegistry>,
    /// Handle into the tokio runtime — used for synchronous-context dispatches
    /// (e.g. `mirage_tun_update_chains` called from the NE dispatch queue).
    rt_handle: tokio::runtime::Handle,
    /// Tokio single-thread runtime — kept alive while the tunnel runs.
    _rt: tokio::runtime::Runtime,
    /// Metrics (bytes rx/tx) — kept alive; values are read via atomic loads
    /// from the Arc clones held by the pump tasks.
    _metrics: Arc<StackMetrics>,
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
/// `write_callback` and `write_ctx` must remain valid until `mirage_tun_stop`.
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

    // Build the write callback wrapper.
    // SAFETY: caller guarantees fn_ptr and ctx are valid for tunnel lifetime.
    let write_cb = Arc::new(unsafe { WriteCallback::new(write_callback, write_ctx) });

    // Build chain registry from initial config.
    let chain_configs: Vec<ChainConfig> = cfg
        .chains
        .iter()
        .map(|c| ChainConfig {
            name: c.name.clone(),
            socks5_addr: c.socks5_addr.to_string(),
            dns_upstream: None,
            protocol: mirage_tun_core::chains::ChainProtocol::Socks5,
        })
        .collect();
    let chain_registry = Arc::new(ChainRegistry::new(chain_configs));

    let cancel = CancellationToken::new();
    let metrics = Arc::new(StackMetrics::default());

    // Capture the runtime handle before block_on so we can store it in TunContext.
    let rt_handle = rt.handle().clone();

    // Register write callback with IosTunStack before calling start().
    // set_write_callback() stores the Arc<WriteCallback> in a static so that
    // TunStack::start() can pick it up and wire the outbound pump correctly.
    let write_cb_for_stack = write_cb.clone();
    let result = rt.block_on(async {
        IosTunStack::set_write_callback(write_cb_for_stack).await;
        IosTunStack::start(cfg, cancel.clone()).await
    });

    match result {
        Ok(_handle) => {
            // _handle contains tcp/udp acceptors — iOS FFI consumers use the
            // raw C entry points (mirage_tun_process_packet) rather than the
            // Rust trait objects, so the handle is intentionally not stored.
            // The write callback pump and inbound pump are already running as
            // tokio tasks owned by the runtime.
        }
        Err(e) => {
            error!("mirage_tun_start: stack start failed: {e}");
            return std::ptr::null_mut();
        }
    }

    let ctx = Box::new(TunContext {
        cancel,
        _write_cb: write_cb,
        chain_registry,
        rt_handle,
        _rt: rt,
        _metrics: metrics,
    });

    info!("mirage_tun_start: tunnel started");
    Box::into_raw(ctx) as *mut c_void
}

// ── Process inbound packet (Swift → Rust) ─────────────────────────────────────

/// Called by Swift for every IP packet read from `packetFlow.readPacketObjects`.
///
/// `data` is a raw IP packet. This function copies the bytes and feeds them
/// into the smoltcp stack via an async channel. Returns immediately (non-blocking).
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

    // Verify ctx is alive (we don't use it directly — inbound_tx is in the static).
    let _ctx = unsafe { &*(ctx as *mut TunContext) };
    let packet = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();

    // Retrieve the sender from the static set during TunStack::start().
    // Non-blocking send — if the channel is full, drop the packet (back-pressure).
    if let Some(tx) = clone_inbound_tx() {
        if tx.try_send(packet).is_err() {
            warn!("mirage_tun_process_packet: inbound channel full, packet dropped");
        }
    } else {
        warn!("mirage_tun_process_packet: stack not started yet, packet dropped");
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
/// The chain registry inside the running stack is atomically replaced.
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

    let ctx_ref = unsafe { &*(ctx as *mut TunContext) };
    let bytes = unsafe { std::slice::from_raw_parts(json, json_len) };

    match parse_chains_json(bytes) {
        Ok(entries) => {
            let count = entries.len();
            let registry = ctx_ref.chain_registry.clone();
            // block_on drives the async update synchronously from the NE
            // dispatch queue (which is outside the tokio runtime context).
            ctx_ref.rt_handle.block_on(async move {
                let new_map = entries
                    .into_iter()
                    .map(|e| (e.name, mirage_tun_core::chains::ChainEntry {
                        socks5_addr: e.socks5_addr,
                        dns_upstream: None,
                    }))
                    .collect();
                registry.update(new_map).await;
            });
            info!("mirage_tun_update_chains: updated {} chains", count);
        }
        Err(e) => {
            warn!("mirage_tun_update_chains: parse error: {e}");
        }
    }
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
    #[serde(default)]
    dns_upstream: Option<String>,
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

fn parse_chains_json(json: &[u8]) -> Result<Vec<ChainEntry>, serde_json::Error> {
    #[derive(serde::Deserialize)]
    struct FfiChain {
        name: String,
        socks5_addr: String,
    }

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
