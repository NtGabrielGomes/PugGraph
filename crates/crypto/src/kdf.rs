use crate::error::CryptoError;
use argon2::Argon2;

pub const SALT_LEN: usize = 16;

pub fn derive_kek(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

pub fn random_salt() -> [u8; SALT_LEN] {
    crate::os_random::<SALT_LEN>()
}
