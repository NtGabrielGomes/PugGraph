use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("nmap parse error: {0}")]
    Parse(String),
}
