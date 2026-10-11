//! macOS TUN stack implementation for mirage2tun.
//!
//! Provides `MacosTunStack` which implements `mirage_tun_core::traits::TunStack`.
//! Uses the native macOS utun kernel control socket for the TUN device and
//! mirage-tcpip-stack (smoltcp) for userspace TCP/UDP demultiplexing.

pub mod api;
pub mod conn_registry;
pub mod dns;
pub mod dns_query_log;
pub mod error;
pub mod firewall;
pub mod kernel_tcp;
pub mod kernel_udp;
pub mod metrics;
pub mod route_monitor;
pub mod routing;
pub mod runtime_guard;
pub mod smoltcp_acceptor;
pub mod stack;
pub mod tun_device;
pub mod udp_forward;

pub use stack::MacosTunStack;
