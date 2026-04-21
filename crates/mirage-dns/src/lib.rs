pub mod cache;
pub mod doh;
pub mod protocol;
pub mod resolver;

pub use resolver::{DnsConfig, DnsError, DnsResolver};
