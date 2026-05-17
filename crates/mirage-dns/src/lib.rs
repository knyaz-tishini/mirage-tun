pub mod cache;
pub mod doh;
pub mod protocol;
pub mod resolver;
pub mod topology_stub;

pub use resolver::{DnsConfig, DnsError, DnsResolver};
pub use topology_stub::DnsRoutingHint;
