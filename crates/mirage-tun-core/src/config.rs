#[derive(Debug, Clone)]
pub struct TunConfig {
    pub tun_name: String,
    pub tun_addr: String,
    pub mtu: u16,
    pub dns_hijack: bool,
    pub intercept: InterceptStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptStrategy {
    KernelRedirect,
    UserspaceNat,
    IpStack,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            tun_name: "mirage0".into(),
            tun_addr: "10.0.85.1/24".into(),
            mtu: 1500,
            dns_hijack: true,
            intercept: InterceptStrategy::IpStack,
        }
    }
}
