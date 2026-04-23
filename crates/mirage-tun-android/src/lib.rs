//! mirage-tun-android — Android VPN TUN stack implementation.
//!
//! Kotlin's `VpnService.Builder.establish()` returns a raw TUN fd.
//! That fd is passed to Rust via JNI. Rust uses smoltcp (mirage-tcpip-stack)
//! to reassemble TCP streams and UDP datagrams from raw IP packets.
//!
//! # Crate types
//! Built as both `cdylib` (Android .so) and `lib` (for cross-compilation check).

pub mod dns;
pub mod error;
pub mod jni_bridge;
pub mod stack;
pub mod vpn_service;

pub use stack::AndroidTunStack;
