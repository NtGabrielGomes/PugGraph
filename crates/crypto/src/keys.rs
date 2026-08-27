use crate::b64::b64e;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct OperatorSecret {
    signing: SigningKey,
    wrapping: StaticSecret,
}

#[derive(Clone)]
pub struct OperatorPublic {
    pub signing: VerifyingKey,
    pub wrapping: PublicKey,
}

impl OperatorSecret {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::from_bytes(&crate::os_random::<32>()),
            wrapping: StaticSecret::from(crate::os_random::<32>()),
        }
    }

    pub fn public(&self) -> OperatorPublic {
        OperatorPublic {
            signing: self.signing.verifying_key(),
            wrapping: PublicKey::from(&self.wrapping),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn wrapping_secret(&self) -> &StaticSecret {
        &self.wrapping
    }

    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.wrapping.to_bytes());
        Zeroizing::new(out)
    }

    pub fn from_secret_bytes(bytes: &[u8; 64]) -> Self {
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[..32]);
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes[32..]);
        Self {
            signing: SigningKey::from_bytes(&s),
            wrapping: StaticSecret::from(w),
        }
    }
}

impl OperatorPublic {
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(sig);
        self.signing.verify(msg, &sig).is_ok()
    }

    pub fn signing_b64(&self) -> String {
        b64e(self.signing.as_bytes())
    }

    pub fn wrapping_b64(&self) -> String {
        b64e(self.wrapping.as_bytes())
    }
}
