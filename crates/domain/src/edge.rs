use crate::ids::{EdgeId, NodeId};
use crate::provenance::{Confidence, Provenance};
use serde::{Deserialize, Serialize};

/// The closed set of relation kinds. Grouped by the abuse/structure they encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /* identity & privilege */
    MemberOf,
    AdminTo,
    HasLocalAdmin,
    Owns,
    WriteDacl,
    GenericAll,
    ForceChangePassword,
    AddMember,
    PrivEsc,
    ShadowCredentials,
    WriteSpn,
    AllowedToAct,
    AllowedToDelegate,
    ReadGmsaPassword,
    ReadLapsPassword,
    GenericWrite,
    WriteOwner,
    AllExtendedRights,
    WriteGpLink,
    AddSelf,

    /* delegation & roasting */
    UnconstrainedDelegation,
    CanKerberoast,
    CanAsrepRoast,

    /* adcs (certificate services) */
    Enroll,
    EnrollOnBehalfOf,
    PublishedTo,
    AuthenticatesAs,

    /* structural & trust */
    MemberOfDomain,
    ContainsOu,
    LinkedGpo,
    GpoAppliesTo,
    DcFor,
    Trusts,
    DcSync,
    ManageCa,

    /* session & credential */
    HasSession,
    CredentialValidFor,
    DumpedFrom,

    /* remote execution */
    CanRdp,
    CanPsRemote,
    ExecuteDcom,
    CanSsh,
    SqlAdmin,
    SqlLink,
    Coerce,
    RelayTo,

    /* hosting & network reach */
    HostsVm,
    VmHostedOn,
    RunsContainer,
    ListensOn,
    HostedOn,
    ConnectsTo,
    RoutesThrough,
    SameSegment,
    ParentSegment,
    ReachableFrom,

    /* findings & loot */
    Affects,
    LootedFrom,
    YieldsCredential,
    EvidenceFor,

    /* operator actions */
    PivotEstablished,
    LateralMovement,
    ExploitableVia,
    Custom,
}

impl EdgeKind {
    pub fn is_traversable(self) -> bool {
        !matches!(
            self,
            EdgeKind::SameSegment
                | EdgeKind::ParentSegment
                | EdgeKind::ContainsOu
                | EdgeKind::MemberOfDomain
                | EdgeKind::PublishedTo
                | EdgeKind::Affects
                | EdgeKind::LootedFrom
                | EdgeKind::YieldsCredential
                | EdgeKind::EvidenceFor
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub kind: EdgeKind,

    pub source: NodeId,
    pub target: NodeId,

    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub evidence: Vec<String>,

    pub provenance: Provenance,
}

impl Edge {
    pub fn new(
        id: EdgeId,
        kind: EdgeKind,
        source: NodeId,
        target: NodeId,
        provenance: Provenance,
    ) -> Self {
        Self {
            id,
            kind,
            source,
            target,
            confidence: Confidence::default(),
            fields: serde_json::Map::new(),
            evidence: Vec::new(),
            provenance,
        }
    }
}
