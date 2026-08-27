use crate::ids::{OperatorId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Suspected,
    Possible,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Suspected
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "tool")]
pub enum Source {
    Manual,
    Import(String),
    Inference,
}

impl Default for Source {
    fn default() -> Self {
        Source::Manual
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompromiseLevel {
    Unknown,
    None,
    User,
    Admin,
    System,
    DomainAdmin,
}

impl Default for CompromiseLevel {
    fn default() -> Self {
        CompromiseLevel::Unknown
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub author: OperatorId,

    #[serde(default)]
    pub source: Source,
    #[serde(default)]
    pub confidence: Confidence,

    pub first_seen: Timestamp,
    pub last_verified: Timestamp,
}

impl Provenance {
    pub fn manual(author: OperatorId, now: Timestamp) -> Self {
        Self {
            author,
            source: Source::Manual,
            confidence: Confidence::Confirmed,
            first_seen: now,
            last_verified: now,
        }
    }
}
