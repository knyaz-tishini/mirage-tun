use thiserror::Error;

#[derive(Error, Debug)]
pub enum MacosTunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("utun socket creation failed: {0}")]
    UtunCreate(String),

    #[error("utun ioctl failed (CTLIOCGINFO): {0}")]
    UtunIoctl(String),

    #[error("utun connect failed: {0}")]
    UtunConnect(String),

    #[error("utun getsockopt (IFNAME) failed: {0}")]
    UtunIfname(String),

    #[error("ifconfig command failed: {0}")]
    Ifconfig(String),

    #[error("pfctl command failed (exit {code}): {stderr}")]
    Pfctl { code: i32, stderr: String },

    #[error("route command failed (exit {code}): {stderr}")]
    Route { code: i32, stderr: String },

    #[error("dns setup failed: {0}")]
    Dns(String),

    #[error("networksetup command failed (exit {code}): {stderr}")]
    Networksetup { code: i32, stderr: String },

    #[error("failed to parse gateway from route output: {0}")]
    GatewayParse(String),

    #[error("tcp intercept listener bind failed: {0}")]
    ListenerBind(std::io::Error),

    #[error("original destination recovery failed: {0}")]
    OrigDst(String),

    #[error("core: {0}")]
    Core(#[from] mirage_tun_core::error::TunError),

    #[error("{0}")]
    Other(String),
}
