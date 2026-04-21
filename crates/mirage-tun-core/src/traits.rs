use std::net::IpAddr;

pub trait PlatformTun: Send + Sync {
    type Error: std::fmt::Display;
    fn name(&self) -> &str;
}

pub trait PlatformFirewall: Send + Sync {
    type Error: std::fmt::Display;
    fn activate(
        &mut self,
        relay_addrs: &[IpAddr],
        tun_name: &str,
        exempt_ports: &[u16],
    ) -> std::result::Result<(), Self::Error>;
    fn deactivate(&mut self) -> std::result::Result<(), Self::Error>;
}

pub trait PlatformRouting: Send + Sync {
    type Error: std::fmt::Display;
    fn set_default_route(&mut self) -> std::result::Result<(), Self::Error>;
    fn restore_routes(&mut self) -> std::result::Result<(), Self::Error>;
    fn add_bypass(&mut self, addr: IpAddr) -> std::result::Result<(), Self::Error>;
    fn original_gateway(&self) -> Option<&str>;
    fn original_interface_idx(&self) -> Option<u32>;
}
