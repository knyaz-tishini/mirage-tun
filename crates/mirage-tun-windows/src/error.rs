#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("wintun: {0}")]
    Wintun(String),
    #[error("routing: {0}")]
    Routing(String),
    #[error("io: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("adapter not ready")]
    AdapterNotReady,
    #[error("tun already active")]
    AlreadyActive,
    #[error("tun not active")]
    NotActive,
    #[error("wfp: {0}")]
    Wfp(String),
    #[error("netstack build: {0}")]
    SmoltcpBuild(std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TunError>;
