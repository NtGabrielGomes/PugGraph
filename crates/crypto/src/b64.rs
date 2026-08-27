use crate::error::CryptoError;
use base64::{engine::general_purpose::STANDARD, Engine};

pub fn b64e(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64d(s: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD.decode(s).map_err(|_| CryptoError::Base64)
}

pub fn b64d_array<const N: usize>(s: &str) -> Result<[u8; N], CryptoError> {
    let v = b64d(s)?;
    v.try_into().map_err(|_| CryptoError::BadKey)
}
