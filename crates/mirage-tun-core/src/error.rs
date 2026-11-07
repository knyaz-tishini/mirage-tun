#[derive(thiserror::Error, Debug)]
pub enum TunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("smoltcp build: {0}")]
    SmoltcpBuild(String),
    #[error("routing: {0}")]
    Routing(String),
    #[error("firewall: {0}")]
    Firewall(String),
    #[error("dns: {0}")]
    Dns(String),
    #[error("chain not found: {0}")]
    ChainNotFound(String),
    #[error("device not open")]
    DeviceNotOpen,
    #[error("{0}")]
    Other(String),
}
