use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKeyKind {
    IpAddress,
    Fqdn,
    Hostname,
    MacAddress,
    AdSid,
    AdObjectGuid,
    DomainName,
    AccountUpn,
    AccountSam,
    AzureObjectId,
    AzureAppId,
    Spn,
    CertThumbprint,
    SmtpAddress,
    Url,
    FileSha256,
    Custom,
}


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKey {
    pub kind: IdentityKeyKind,
    pub value: String,
    #[serde(default)]
    pub is_primary: bool,
}

/// Every identity-key kind, in declaration order — the source of truth the web
/// client validates its `IDENTITY_KINDS` list against (see `schema`).
pub const ALL_IDENTITY_KEY_KINDS: [IdentityKeyKind; 17] = {
    use IdentityKeyKind::*;
    [
        IpAddress,
        Fqdn,
        Hostname,
        MacAddress,
        AdSid,
        AdObjectGuid,
        DomainName,
        AccountUpn,
        AccountSam,
        AzureObjectId,
        AzureAppId,
        Spn,
        CertThumbprint,
        SmtpAddress,
        Url,
        FileSha256,
        Custom,
    ]
};

impl IdentityKey {
    pub fn new(kind: IdentityKeyKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
            is_primary: false,
        }
    }

    pub fn primary(kind: IdentityKeyKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
            is_primary: true,
        }
    }

    pub fn index_token(&self) -> String {
        format!("{:?}:{}", self.kind, self.value)
    }
}
