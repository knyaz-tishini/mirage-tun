use mirage_tun_core::error::TunError;

#[derive(thiserror::Error, Debug)]
pub enum IosTunError {
    #[error("json config parse error: {0}")]
    ConfigParse(#[from] serde_json::Error),

    #[error("tokio runtime build failed: {0}")]
    RuntimeBuild(std::io::Error),

    #[error("smoltcp stack build failed: {0}")]
    StackBuild(String),

    #[error("packet channel closed")]
    ChannelClosed,

    #[error("null pointer in FFI argument")]
    NullPointer,

    #[error("core: {0}")]
    Core(#[from] TunError),

    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for IosTunError {
    fn from(e: std::io::Error) -> Self {
        IosTunError::Core(TunError::Io(e))
    }
}
