use std::net::{IpAddr, SocketAddr};
use crate::error::TunError;

#[async_trait::async_trait]
pub trait PlatformTun: Send + Sync {
    async fn create(&mut self) -> Result<(), TunError>;
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;
    async fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunError>;
    fn name(&self) -> &str;
    fn destroy(&mut self);
}

pub trait PlatformFirewall: Send + Sync {
    fn activate(
        &mut self,
        relay_addrs: &[SocketAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> Result<(), TunError>;
    fn deactivate(&mut self) -> Result<(), TunError>;
}

pub trait PlatformRouting: Send + Sync {
    fn set_default_route(&mut self, tun_name: &str) -> Result<(), TunError>;
    fn restore_routes(&mut self) -> Result<(), TunError>;
    fn add_bypass(&mut self, addr: IpAddr) -> Result<(), TunError>;
}
