use crate::ids::{OperatorId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operator {
    pub id: OperatorId,
    pub display_name: String,

    pub signing_public_key: String,
    pub wrapping_public_key: String,

    #[serde(default)]
    pub role: OperatorRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Lead,
    Operator,
    Observer,
    Auditor,
}

impl Default for OperatorRole {
    fn default() -> Self {
        OperatorRole::Operator
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub author: OperatorId,
    pub at: Timestamp,

    pub action: String,
    pub summary: String,

    #[serde(default)]
    pub prev_hash: String,
}
