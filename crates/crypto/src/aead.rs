use crate::b64::{b64d, b64e};
use crate::error::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    pub nonce: String,
    pub ct: String,
}

pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> SealedBlob {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = crate::os_random::<XNONCE_LEN>();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption does not fail for in-memory inputs");
    SealedBlob {
        nonce: b64e(&nonce),
        ct: b64e(&ct),
    }
}

pub fn open(key: &[u8; KEY_LEN], blob: &SealedBlob, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce = b64d(&blob.nonce)?;
    if nonce.len() != XNONCE_LEN {
        return Err(CryptoError::BadKey);
    }
    let ct = b64d(&blob.ct)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}
