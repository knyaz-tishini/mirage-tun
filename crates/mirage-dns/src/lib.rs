pub mod cache;
pub mod doh;
pub mod forward_cache;
pub mod protocol;
pub mod resolver;
pub mod topology_stub;

pub use forward_cache::{ForwardCache, ForwardError};
pub use resolver::{DnsConfig, DnsError, DnsResolver};
pub use topology_stub::DnsRoutingHint;
