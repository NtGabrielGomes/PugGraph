use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("aead authentication failed")]
    Decrypt,
    #[error("malformed key material")]
    BadKey,
    #[error("base64 decode error")]
    Base64,
    #[error("argon2 key derivation error: {0}")]
    Kdf(String),
    #[error("malformed campaign file: {0}")]
    File(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("no campaign-key envelope for this operator")]
    NotARecipient,
}
