use crate::aead::{open, seal, SealedBlob, KEY_LEN};
use crate::b64::{b64d_array, b64e};
use crate::error::CryptoError;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const WRAP_INFO: &[u8] = b"campaign-key-wrap-v1";

fn derive_kek(shared: &[u8; 32], eph_pub: &[u8; 32], recip_pub: &[u8; 32]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(WRAP_INFO.len() + 64);
    info.extend_from_slice(WRAP_INFO);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recip_pub);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub eph_pub: String,
    pub blob: SealedBlob,
}

pub fn wrap_key(plain: &[u8; KEY_LEN], recipient: &PublicKey) -> WrappedKey {
    let eph: StaticSecret = StaticSecret::from(crate::os_random::<32>());
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(recipient);
    let kek = derive_kek(shared.as_bytes(), eph_pub.as_bytes(), recipient.as_bytes());
    let blob = seal(&kek, plain, WRAP_INFO);
    WrappedKey {
        eph_pub: b64e(eph_pub.as_bytes()),
        blob,
    }
}

pub fn unwrap_key(w: &WrappedKey, recipient: &StaticSecret) -> Result<[u8; KEY_LEN], CryptoError> {
    let eph_pub = PublicKey::from(b64d_array::<32>(&w.eph_pub)?);
    let recip_pub = PublicKey::from(recipient);
    let shared = recipient.diffie_hellman(&eph_pub);
    let kek = derive_kek(shared.as_bytes(), eph_pub.as_bytes(), recip_pub.as_bytes());
    let pt = open(&kek, &w.blob, WRAP_INFO)?;
    pt.try_into().map_err(|_| CryptoError::BadKey)
}
