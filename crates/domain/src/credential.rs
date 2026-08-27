use crate::ids::{CredentialId, NodeId, Timestamp};
use crate::provenance::Provenance;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    PasswordPlaintext,
    PasswordNtlm,
    PasswordNetNtlmv2,
    KerberosTicket,
    KerberosKey,
    SshKey,
    ApiKey,
    Token,
    Cookie,
    Certificate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityState {
    Unknown,
    Valid,
    Invalid,
    Expired,
    Rotated,
}

impl Default for ValidityState {
    fn default() -> Self {
        ValidityState::Unknown
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    Dump,
    Spray,
    Phishing,
    Mitm,
    ServiceExploit,
    ConfigFile,
    MemoryDump,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TestResult {
    pub host: NodeId,
    pub succeeded: bool,
    pub at: Timestamp,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,
    pub username: String,
    #[serde(default)]
    pub domain: Option<String>,
    pub credential_type: CredentialType,

    #[serde(default)]
    pub secret_sealed: Option<String>,

    #[serde(default)]
    pub belongs_to: Option<NodeId>,
    #[serde(default)]
    pub obtained_from: Option<NodeId>,

    #[serde(default)]
    pub validity: ValidityState,
    pub validity_as_of: Timestamp,

    pub source: CredentialSource,
    #[serde(default)]
    pub tested_against: Vec<TestResult>,

    pub provenance: Provenance,
}
