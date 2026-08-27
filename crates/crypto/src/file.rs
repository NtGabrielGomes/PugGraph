use crate::aead::SealedBlob;
use crate::error::CryptoError;
use crate::wrap::WrappedKey;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 4] = b"CAMP";
pub const FORMAT_VERSION: u8 = 2;

pub const MIN_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub operator_id: String,
    pub signing_public_key: String,
    pub wrapped_campaign_key: WrappedKey,
    #[serde(default)]
    pub wrapped_vault_key: Option<WrappedKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignFileHeader {
    pub format_version: u8,
    pub campaign_id: String,
    pub recipients: Vec<Recipient>,
    pub snapshot_version: u64,
    #[serde(default)]
    pub key_epoch: u64,
}

impl CampaignFileHeader {
    pub fn recipient(&self, operator_id: &str) -> Option<&Recipient> {
        self.recipients
            .iter()
            .find(|r| r.operator_id == operator_id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CampaignFile {
    pub header: CampaignFileHeader,
    pub sealed_snapshot: SealedBlob,
}

impl CampaignFile {
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let header =
            serde_json::to_vec(&self.header).map_err(|e| CryptoError::Serde(e.to_string()))?;
        let payload = serde_json::to_vec(&self.sealed_snapshot)
            .map_err(|e| CryptoError::Serde(e.to_string()))?;

        let mut out = Vec::with_capacity(13 + header.len() + payload.len());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cur = 0usize;
        let take = |cur: &mut usize, n: usize| -> Result<std::ops::Range<usize>, CryptoError> {
            let end = cur
                .checked_add(n)
                .ok_or_else(|| CryptoError::File("overflow".into()))?;
            if end > bytes.len() {
                return Err(CryptoError::File("truncated".into()));
            }
            let r = *cur..end;
            *cur = end;
            Ok(r)
        };

        if &bytes[take(&mut cur, 4)?] != MAGIC {
            return Err(CryptoError::File("bad magic".into()));
        }
        let version = bytes[take(&mut cur, 1)?][0];
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&version) {
            return Err(CryptoError::File("unsupported format version".into()));
        }

        let hlen = u32::from_le_bytes(bytes[take(&mut cur, 4)?].try_into().unwrap()) as usize;
        let header: CampaignFileHeader = serde_json::from_slice(&bytes[take(&mut cur, hlen)?])
            .map_err(|e| CryptoError::File(e.to_string()))?;
        let plen = u32::from_le_bytes(bytes[take(&mut cur, 4)?].try_into().unwrap()) as usize;
        let sealed_snapshot: SealedBlob = serde_json::from_slice(&bytes[take(&mut cur, plen)?])
            .map_err(|e| CryptoError::File(e.to_string()))?;

        Ok(Self {
            header,
            sealed_snapshot,
        })
    }
}
