#[derive(thiserror::Error, Debug)]
pub enum TunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
