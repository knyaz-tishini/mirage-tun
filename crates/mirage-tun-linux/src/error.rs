use mirage_tun_core::error::TunError;

#[derive(thiserror::Error, Debug)]
pub enum LinuxTunError {
    #[error("tun open failed: {0}")]
    Open(#[from] std::io::Error),
    #[error("nftables error (exit {code}): {stderr}")]
    Nftables { code: i32, stderr: String },
    #[error("iptables error (exit {code}): {stderr}")]
    Iptables { code: i32, stderr: String },
    #[error("ip command failed: {0}")]
    Routing(String),
    #[error("resolvectl failed: {0}")]
    Dns(String),
    #[error("core: {0}")]
    Core(#[from] TunError),
    #[error("{0}")]
    Other(String),
}
