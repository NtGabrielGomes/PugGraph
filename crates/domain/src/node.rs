use crate::ids::NodeId;
use crate::identity::IdentityKey;
use crate::provenance::{CompromiseLevel, Provenance};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /* hosts */
    HostWindows,
    HostLinux,
    HostMacos,
    NetworkDevice,

    /* virtualization */
    Hypervisor,
    VirtualMachine,
    Container,
    ContainerHost,

    /* active directory */
    Domain,
    Forest,
    OrganizationalUnit,
    Gpo,
    DomainController,
    CertificateAuthority,
    CertTemplate,

    /* network */
    NetworkSegment,
    Subnet,
    Vlan,
    
    /* services */
    Service,
    Share,
    WebApplication,

    /* identities */
    UserAccount,
    ComputerAccount,
    ServiceAccount,
    Group,

    /* cloud */
    CloudResource,
    CloudIdentity,

    /* findings & loot */
    Finding,
    Loot,

    /* escape hatch */
    Custom,
}

impl NodeKind {
    pub fn is_high_value(self) -> bool {
        matches!(
            self,
            NodeKind::DomainController
                | NodeKind::CertificateAuthority
                | NodeKind::Domain
                | NodeKind::Forest
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,

    pub label: String,

    #[serde(default)]
    pub identity_keys: Vec<IdentityKey>,
    #[serde(default)]
    pub compromise_level: CompromiseLevel,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub tags: BTreeSet<String>,

    pub provenance: Provenance,
}

impl Node {
    pub fn new(id: NodeId, kind: NodeKind, label: impl Into<String>, provenance: Provenance) -> Self {
        Self {
            id,
            kind,
            label: label.into(),
            identity_keys: Vec::new(),
            compromise_level: CompromiseLevel::default(),
            fields: serde_json::Map::new(),
            tags: BTreeSet::new(),
            provenance,
        }
    }

    pub fn with_identity(mut self, key: IdentityKey) -> Self {
        self.identity_keys.push(key);
        self
    }
}
