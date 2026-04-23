//! JNI entry points called from Kotlin `MirageNative`.
//!
//! All functions are gated with `#[cfg(target_os = "android")]`.
//! Non-Android builds compile empty stubs so the crate can be
//! `cargo check`-ed on Windows during development.
//!
//! # Kotlin companion class
//! ```kotlin
//! package com.mirage.vpn
//! object MirageNative {
//!     external fun start(fd: Int, configJson: String): Boolean
//!     external fun stop()
//!     external fun updateChains(json: String)
//!     external fun setVpnService(vpnService: VpnService)
//!     init { System.loadLibrary("mirage2tun") }
//! }
//! ```

use std::sync::OnceLock;

/// Pending TUN fd — set before `start()` launches the tokio runtime.
/// `stack.rs` calls `take_pending_fd()` during `TunStack::start()`.
static PENDING_FD: OnceLock<std::sync::Mutex<Option<i32>>> = OnceLock::new();

/// Consume the fd stored by the JNI `start` function.
pub(crate) fn take_pending_fd() -> Option<i32> {
    PENDING_FD
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

fn store_pending_fd(fd: i32) {
    *PENDING_FD
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(fd);
}

// ── Android-only JNI functions ────────────────────────────────────────────────

#[cfg(target_os = "android")]
mod android {
    use super::store_pending_fd;

    use jni::{
        objects::{JClass, JObject, JString},
        sys::{jboolean, jint, JNI_FALSE, JNI_TRUE},
        JNIEnv,
    };
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info};

    use crate::{
        error::AndroidTunError,
        stack::AndroidTunStack,
        vpn_service::SocketProtector,
    };
    use mirage_tun_core::{stack_config::StackConfig, traits::TunStack};

    // ── Global runtime state ──────────────────────────────────────────────────

    struct RunState {
        cancel: CancellationToken,
        /// Store SocketProtector so protect() can be called later.
        _protector: SocketProtector,
    }

    static RUN_STATE: std::sync::OnceLock<std::sync::Mutex<Option<RunState>>> =
        std::sync::OnceLock::new();

    fn run_state() -> &'static std::sync::Mutex<Option<RunState>> {
        RUN_STATE.get_or_init(|| std::sync::Mutex::new(None))
    }

    // ── JNI: start ────────────────────────────────────────────────────────────

    /// Called from Kotlin to start the VPN stack.
    ///
    /// ```kotlin
    /// MirageNative.start(fd = pfd.fd, configJson = json)
    /// ```
    ///
    /// Returns `true` on success, `false` on failure.
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_start(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        fd: jint,
        config_json: JString<'_>,
    ) -> jboolean {
        let config_str: String = match env.get_string(&config_json) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("start: get_string failed: {e}");
                return JNI_FALSE;
            }
        };

        let cfg: StackConfig = match serde_json::from_str(&config_str) {
            Ok(c) => c,
            Err(e) => {
                error!("start: config JSON parse failed: {e}");
                return JNI_FALSE;
            }
        };

        {
            let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
            if state.is_some() {
                error!("start: already running");
                return JNI_FALSE;
            }

            let cancel = CancellationToken::new();
            let cancel_clone = cancel.clone();

            // Store fd so TunStack::start() can retrieve it.
            store_pending_fd(fd);

            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("mirage-android")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("start: tokio runtime build failed: {e}");
                    return JNI_FALSE;
                }
            };

            let result: Result<(), AndroidTunError> = rt.block_on(async move {
                let _handle = AndroidTunStack::start(cfg, cancel_clone).await?;
                // _handle contains tcp/udp acceptors — consumer would use them here.
                // For now, we park the stack; real usage spawns connection handlers.
                Ok(())
            });

            match result {
                Ok(()) => {
                    *state = Some(RunState {
                        cancel,
                        _protector: SocketProtector::new(),
                    });
                    info!("start: VPN stack up");
                    JNI_TRUE
                }
                Err(e) => {
                    error!("start: stack failed: {e}");
                    JNI_FALSE
                }
            }
        }
    }

    // ── JNI: stop ─────────────────────────────────────────────────────────────

    /// Called from Kotlin to stop the VPN stack.
    ///
    /// ```kotlin
    /// MirageNative.stop()
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_stop(
        _env: JNIEnv<'_>,
        _class: JClass<'_>,
    ) {
        let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = state.take() {
            s.cancel.cancel();
            info!("stop: cancellation sent");
        }
    }

    // ── JNI: updateChains ─────────────────────────────────────────────────────

    /// Hot-reload chain list without restarting the stack.
    ///
    /// ```kotlin
    /// MirageNative.updateChains(json = "[{\"name\":\"default\",\"socks5_addr\":\"...\"}, ...]")
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_updateChains(
        mut env: JNIEnv<'_>,
        _class: JClass<'_>,
        json: JString<'_>,
    ) {
        let _json_str: String = match env.get_string(&json) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("updateChains: get_string failed: {e}");
                return;
            }
        };
        // Chain updates are handled by the running stack via its own channel.
        // This is a placeholder — a real implementation would post to a
        // `mpsc::Sender<Vec<ChainEntry>>` stored in global state.
    }

    // ── JNI: setVpnService ────────────────────────────────────────────────────

    /// Pass the Kotlin `VpnService` instance to Rust so `protect(fd)` can be called.
    ///
    /// ```kotlin
    /// MirageNative.setVpnService(this)   // `this` = VpnService instance
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_mirage_vpn_MirageNative_setVpnService(
        env: JNIEnv<'_>,
        _class: JClass<'_>,
        vpn_service: JObject<'_>,
    ) {
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                error!("setVpnService: get_java_vm failed: {e}");
                return;
            }
        };
        let global_ref = match env.new_global_ref(vpn_service) {
            Ok(r) => r,
            Err(e) => {
                error!("setVpnService: new_global_ref failed: {e}");
                return;
            }
        };

        // Store the SocketProtector in run state if already running,
        // or in a pre-start cell for pickup by `start`.
        let protector = SocketProtector::new(vm, global_ref);

        let mut state = run_state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = state.as_mut() {
            s._protector = protector;
        }
        // If not yet running, the next `start` call should pass VpnService there too.
        // This is handled by calling setVpnService before start in Kotlin.
    }
}

// ── Non-Android stubs ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
mod stubs {
    // Empty — on non-Android builds the JNI functions are not exposed.
    // `cargo check` on Windows validates the rest of the crate compiles.
}
