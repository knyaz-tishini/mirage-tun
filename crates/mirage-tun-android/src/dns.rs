use std::net::IpAddr;

use async_trait::async_trait;
use mirage_tun_core::{error::TunError, traits::private};

/// No-op DNS implementation for Android.
///
/// DNS is configured in Kotlin via `VpnService.Builder.addDnsServer()`.
/// Rust has nothing to do for DNS setup on Android.
pub struct AndroidDns;

impl private::Sealed for AndroidDns {}

#[async_trait]
impl mirage_tun_core::traits::PlatformDns for AndroidDns {
    type Error = TunError;

    async fn set_dns(&mut self, _tun_name: &str, _servers: &[IpAddr]) -> Result<(), Self::Error> {
        // DNS is set via VpnService.Builder.addDnsServer() in Kotlin.
        Ok(())
    }

    async fn revert_dns(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
