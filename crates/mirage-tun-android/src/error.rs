/// Errors produced by the Android TUN implementation.
#[derive(thiserror::Error, Debug)]
pub enum AndroidTunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("smoltcp stack build: {0}")]
    SmoltcpBuild(String),

    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),

    #[error("jni: {0}")]
    Jni(String),

    #[error("already running")]
    AlreadyRunning,

    #[error("not running")]
    NotRunning,

    #[error("{0}")]
    Other(String),
}
