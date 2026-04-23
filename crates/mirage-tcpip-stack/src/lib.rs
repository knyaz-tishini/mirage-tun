// ── smoltcp inlined (forked from smoltcp 0.12.0) ────────────────────────────

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]

#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::identity_op)]
#![allow(clippy::option_map_unit_fn)]
#![allow(clippy::unit_arg)]
#![allow(clippy::new_without_default)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(not(any(
    feature = "proto-ipv4",
    feature = "proto-ipv6",
    feature = "proto-sixlowpan"
)))]
compile_error!("You must enable at least one of the following features: proto-ipv4, proto-ipv6, proto-sixlowpan");

#[cfg(all(
    feature = "socket",
    not(any(
        feature = "socket-raw",
        feature = "socket-udp",
        feature = "socket-tcp",
        feature = "socket-icmp",
        feature = "socket-dhcpv4",
        feature = "socket-dns",
    ))
))]
compile_error!("If you enable the socket feature, you must enable at least one socket type feature");

#[cfg(all(
    feature = "socket",
    not(any(
        feature = "medium-ethernet",
        feature = "medium-ip",
        feature = "medium-ieee802154",
    ))
))]
compile_error!("If you enable the socket feature, you must enable at least one medium feature");

// smoltcp modules inlined at crate root
#[macro_use]
mod macros;
mod parsers;
mod smoltcp_rand;

pub mod config {
    pub use crate::smoltcp_config::*;
}

mod smoltcp_config;

#[cfg(any(
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "medium-ieee802154"
))]
pub mod iface;

pub mod phy;
#[cfg(feature = "socket")]
pub mod socket;
pub mod storage;
pub mod time;
pub mod wire;

#[cfg(all(
    test,
    any(
        feature = "medium-ethernet",
        feature = "medium-ip",
        feature = "medium-ieee802154"
    )
))]
mod tests;

// ── mirage-tcpip-stack wrapper ────────────────────────────────────────────────

mod device;

mod runner;
pub use runner::Runner;

mod packet;
pub use packet::AnyIpPktFrame;

mod filter;
pub use filter::{IpFilter, IpFilters};

pub mod udp;
pub use udp::UdpSocket;

pub mod tcp;
pub use tcp::{TcpListener, TcpStream};

pub mod stack;
pub use stack::{Stack, StackBuilder};
