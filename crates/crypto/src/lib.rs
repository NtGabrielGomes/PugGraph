pub mod aead;
mod b64;
pub mod error;
pub mod file;
pub mod kdf;
pub mod keys;
pub mod wrap;

pub use aead::{open, seal, SealedBlob, KEY_LEN};
pub use error::CryptoError;
pub use file::{CampaignFile, CampaignFileHeader, Recipient, FORMAT_VERSION};
pub use keys::{OperatorPublic, OperatorSecret};
pub use wrap::{unwrap_key, wrap_key, WrappedKey};

use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

/// Fill a fixed-size array with cryptographically secure bytes straight from the
/// OS CSPRNG. This is the crate's single entropy source: the dalek key types are
/// built from these bytes via their `from_bytes`/`From` constructors rather than
/// by handing them an RNG, because their generators are still pinned to the
/// older `rand_core` and can't accept a `rand` 0.10 generator.
pub(crate) fn os_random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    SysRng
        .try_fill_bytes(&mut buf)
        .expect("OS RNG (getrandom) must not fail");
    buf
}

pub struct CampaignKeys {
    campaign_key: Zeroizing<[u8; KEY_LEN]>,
    vault_key: Option<Zeroizing<[u8; KEY_LEN]>>,
}

const VAULT_AAD: &[u8] = b"campaign-credential-vault-v1";

impl CampaignKeys {
    pub fn generate() -> Self {
        Self {
            campaign_key: Zeroizing::new(os_random::<KEY_LEN>()),
            vault_key: Some(Zeroizing::new(os_random::<KEY_LEN>())),
        }
    }

    pub fn campaign_key(&self) -> &[u8; KEY_LEN] {
        &self.campaign_key
    }

    pub fn has_vault(&self) -> bool {
        self.vault_key.is_some()
    }

    fn content_aad(campaign_id: &str, epoch: u64) -> Vec<u8> {
        if epoch == 0 {
            campaign_id.as_bytes().to_vec()
        } else {
            format!("{campaign_id}:{epoch}").into_bytes()
        }
    }

    pub fn seal_content_at(&self, campaign_id: &str, epoch: u64, plaintext: &[u8]) -> SealedBlob {
        seal(
            &self.campaign_key,
            plaintext,
            &Self::content_aad(campaign_id, epoch),
        )
    }

    pub fn open_content_at(
        &self,
        campaign_id: &str,
        epoch: u64,
        blob: &SealedBlob,
    ) -> Result<Vec<u8>, CryptoError> {
        open(
            &self.campaign_key,
            blob,
            &Self::content_aad(campaign_id, epoch),
        )
    }

    pub fn seal_content(&self, campaign_id: &str, plaintext: &[u8]) -> SealedBlob {
        self.seal_content_at(campaign_id, 0, plaintext)
    }

    pub fn open_content(
        &self,
        campaign_id: &str,
        blob: &SealedBlob,
    ) -> Result<Vec<u8>, CryptoError> {
        self.open_content_at(campaign_id, 0, blob)
    }

    pub fn seal_secret(&self, plaintext: &[u8]) -> Result<SealedBlob, CryptoError> {
        let vk = self.vault_key.as_ref().ok_or(CryptoError::NotARecipient)?;
        Ok(seal(vk, plaintext, VAULT_AAD))
    }

    pub fn open_secret(&self, blob: &SealedBlob) -> Result<Vec<u8>, CryptoError> {
        let vk = self.vault_key.as_ref().ok_or(CryptoError::NotARecipient)?;
        open(vk, blob, VAULT_AAD)
    }
}

pub fn build_recipient(
    operator_id: impl Into<String>,
    op_public: &OperatorPublic,
    keys: &CampaignKeys,
    grant_vault: bool,
) -> Recipient {
    let wrapped_campaign_key = wrap_key(keys.campaign_key(), &op_public.wrapping);
    let wrapped_vault_key = match (grant_vault, &keys.vault_key) {
        (true, Some(vk)) => Some(wrap_key(vk, &op_public.wrapping)),
        _ => None,
    };

    Recipient {
        operator_id: operator_id.into(),
        signing_public_key: op_public.signing_b64(),
        wrapped_campaign_key,
        wrapped_vault_key,
    }
}

pub fn open_campaign_keys(
    header: &CampaignFileHeader,
    operator_id: &str,
    secret: &OperatorSecret,
) -> Result<CampaignKeys, CryptoError> {
    let r = header
        .recipient(operator_id)
        .ok_or(CryptoError::NotARecipient)?;
    let ck = unwrap_key(&r.wrapped_campaign_key, secret.wrapping_secret())?;
    
    let vault_key = match &r.wrapped_vault_key {
        Some(w) => Some(Zeroizing::new(unwrap_key(w, secret.wrapping_secret())?)),
        None => None,
    };

    Ok(CampaignKeys {
        campaign_key: Zeroizing::new(ck),
        vault_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip_and_tamper_detection() {
        let key = [7u8; KEY_LEN];
        let blob = seal(&key, b"loot", b"campaign-1");
        assert_eq!(open(&key, &blob, b"campaign-1").unwrap(), b"loot");

        assert!(matches!(
            open(&key, &blob, b"campaign-2"),
            Err(CryptoError::Decrypt)
        ));

        assert!(matches!(
            open(&[8u8; KEY_LEN], &blob, b"campaign-1"),
            Err(CryptoError::Decrypt)
        ));

        let mut tampered = blob.clone();
        let mut raw = b64::b64d(&tampered.ct).unwrap();
        raw[0] ^= 0x01;
        tampered.ct = b64::b64e(&raw);
        assert!(matches!(
            open(&key, &tampered, b"campaign-1"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn key_wrap_round_trip_and_wrong_recipient() {
        let alice = OperatorSecret::generate();
        let bob = OperatorSecret::generate();
        let secret = [42u8; KEY_LEN];

        let wrapped = wrap_key(&secret, &alice.public().wrapping);
        assert_eq!(
            unwrap_key(&wrapped, alice.wrapping_secret()).unwrap(),
            secret
        );
        assert!(unwrap_key(&wrapped, bob.wrapping_secret()).is_err());
    }

    #[test]
    fn signing_round_trip() {
        let alice = OperatorSecret::generate();
        let pubk = alice.public();
        let msg = b"node.upsert n1";
        let sig = alice.sign(msg);
        assert!(pubk.verify(msg, &sig));
        assert!(!pubk.verify(b"node.upsert n2", &sig));

        let bob = OperatorSecret::generate();
        assert!(!bob.public().verify(msg, &sig));
    }

    #[test]
    fn kdf_is_deterministic_and_salt_sensitive() {
        let salt = kdf::random_salt();
        let k1 = kdf::derive_kek(b"correct horse battery staple", &salt).unwrap();
        let k2 = kdf::derive_kek(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(k1, k2);
        let k3 = kdf::derive_kek(b"correct horse battery staple", &kdf::random_salt()).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn operator_secret_serialization_round_trip() {
        let alice = OperatorSecret::generate();
        let bytes = alice.to_secret_bytes();
        let restored = OperatorSecret::from_secret_bytes(&bytes);
        let msg = b"x";
        assert!(alice.public().verify(msg, &restored.sign(msg)));
    }

    #[test]
    fn full_campaign_file_flow_with_role_limited_vault() {
        let campaign_id = "camp_01HXYZ";
        let keys = CampaignKeys::generate();

        let lead = OperatorSecret::generate();
        let observer = OperatorSecret::generate();
        let stranger = OperatorSecret::generate();

        let header = CampaignFileHeader {
            format_version: FORMAT_VERSION,
            campaign_id: campaign_id.to_string(),
            recipients: vec![
                build_recipient("op_lead", &lead.public(), &keys, true),
                build_recipient("op_obs", &observer.public(), &keys, false),
            ],
            snapshot_version: 1,
            key_epoch: 0,
        };

        let snapshot = b"<loro-snapshot-bytes>";
        let sealed_snapshot = keys.seal_content(campaign_id, snapshot);
        let sealed_secret = keys.seal_secret(b"P@ssw0rd!").unwrap();

        let file = CampaignFile {
            header,
            sealed_snapshot,
        };
        let encoded = file.encode().unwrap();
        let decoded = CampaignFile::decode(&encoded).unwrap();
        assert_eq!(decoded, file);

        let lead_keys = open_campaign_keys(&decoded.header, "op_lead", &lead).unwrap();
        assert!(lead_keys.has_vault());
        assert_eq!(
            lead_keys
                .open_content(campaign_id, &decoded.sealed_snapshot)
                .unwrap(),
            snapshot
        );
        assert_eq!(lead_keys.open_secret(&sealed_secret).unwrap(), b"P@ssw0rd!");

        let obs_keys = open_campaign_keys(&decoded.header, "op_obs", &observer).unwrap();
        assert!(!obs_keys.has_vault());
        assert_eq!(
            obs_keys
                .open_content(campaign_id, &decoded.sealed_snapshot)
                .unwrap(),
            snapshot
        );
        assert!(matches!(
            obs_keys.open_secret(&sealed_secret),
            Err(CryptoError::NotARecipient)
        ));

        assert!(matches!(
            open_campaign_keys(&decoded.header, "op_ghost", &stranger),
            Err(CryptoError::NotARecipient)
        ));

        let mut corrupt = encoded.clone();
        corrupt[0] ^= 0xFF;
        assert!(matches!(
            CampaignFile::decode(&corrupt),
            Err(CryptoError::File(_))
        ));

        assert!(CampaignFile::decode(&encoded[..3]).is_err());
    }

    #[test]
    fn key_rotation_revokes_a_removed_operator() {
        let campaign = "camp_rot";
        let lead = OperatorSecret::generate();
        let mallory = OperatorSecret::generate();

        let keys_v1 = CampaignKeys::generate();
        let content_v1 = b"<snapshot v1>";
        let header_v1 = CampaignFileHeader {
            format_version: FORMAT_VERSION,
            campaign_id: campaign.to_string(),
            recipients: vec![
                build_recipient("op_lead", &lead.public(), &keys_v1, true),
                build_recipient("op_mal", &mallory.public(), &keys_v1, true),
            ],
            snapshot_version: 1,
            key_epoch: 0,
        };
        let sealed_v1 = keys_v1.seal_content_at(campaign, 0, content_v1);
        let mallory_v1_keys = open_campaign_keys(&header_v1, "op_mal", &mallory).unwrap();
        assert_eq!(
            mallory_v1_keys
                .open_content_at(campaign, 0, &sealed_v1)
                .unwrap(),
            content_v1
        );

        let keys_v2 = CampaignKeys::generate();
        let content_v2 = b"<snapshot v2, post-rotation>";
        let header_v2 = CampaignFileHeader {
            format_version: FORMAT_VERSION,
            campaign_id: campaign.to_string(),
            recipients: vec![build_recipient("op_lead", &lead.public(), &keys_v2, true)],
            snapshot_version: 2,
            key_epoch: 1,
        };
        let sealed_v2 = keys_v2.seal_content_at(campaign, 1, content_v2);

        let lead_v2 = open_campaign_keys(&header_v2, "op_lead", &lead).unwrap();
        assert_eq!(
            lead_v2.open_content_at(campaign, 1, &sealed_v2).unwrap(),
            content_v2
        );

        assert!(lead_v2.open_content_at(campaign, 0, &sealed_v2).is_err());
        assert!(lead_v2.open_content(campaign, &sealed_v2).is_err()); // legacy == epoch 0

        assert!(matches!(
            open_campaign_keys(&header_v2, "op_mal", &mallory),
            Err(CryptoError::NotARecipient)
        ));
        assert!(mallory_v1_keys
            .open_content_at(campaign, 1, &sealed_v2)
            .is_err());
    }

    #[test]
    fn v1_files_decode_with_epoch_zero_and_legacy_aad() {
        let json = r#"{"format_version":1,"campaign_id":"c","recipients":[],"snapshot_version":1}"#;
        let h: CampaignFileHeader = serde_json::from_str(json).unwrap();
        assert_eq!(h.key_epoch, 0);

        let keys = CampaignKeys::generate();
        let file = CampaignFile {
            header: CampaignFileHeader {
                format_version: FORMAT_VERSION,
                campaign_id: "c".into(),
                recipients: vec![],
                snapshot_version: 1,
                key_epoch: 0,
            },
            sealed_snapshot: keys.seal_content("c", b"x"),
        };
        let mut bytes = file.encode().unwrap();
        bytes[4] = 1;
        let decoded = CampaignFile::decode(&bytes).unwrap();
        assert_eq!(decoded.header.key_epoch, 0);
        assert_eq!(
            keys.open_content("c", &decoded.sealed_snapshot).unwrap(),
            b"x"
        );
    }
}
