use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrdtError {
    #[error("loro error: {0}")]
    Loro(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("malformed document: {0}")]
    Malformed(String),
}

impl From<loro::LoroError> for CrdtError {
    fn from(e: loro::LoroError) -> Self {
        CrdtError::Loro(e.to_string())
    }
}

impl From<loro::LoroEncodeError> for CrdtError {
    fn from(e: loro::LoroEncodeError) -> Self {
        CrdtError::Loro(e.to_string())
    }
}

impl From<serde_json::Error> for CrdtError {
    fn from(e: serde_json::Error) -> Self {
        CrdtError::Serde(e.to_string())
    }
}
