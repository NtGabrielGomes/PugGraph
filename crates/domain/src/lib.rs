pub mod constraints;
pub mod credential;
pub mod edge;
pub mod entity;
pub mod identity;
pub mod ids;
pub mod node;
pub mod provenance;
pub mod schema;

pub use constraints::{NodeClass, ALL_EDGE_KINDS, ALL_NODE_KINDS};
pub use identity::ALL_IDENTITY_KEY_KINDS;
pub use credential::{Credential, CredentialSource, CredentialType, TestResult, ValidityState};
pub use edge::{Edge, EdgeKind};
pub use entity::{Event, Operator, OperatorRole};
pub use identity::{IdentityKey, IdentityKeyKind};
pub use ids::{CampaignId, CredentialId, EdgeId, NodeId, OperatorId, Timestamp};
pub use node::{Node, NodeKind};
pub use provenance::{CompromiseLevel, Confidence, Provenance, Source};

#[cfg(test)]
mod tests {
    use super::*;

    fn op() -> OperatorId {
        OperatorId::new("op_alice")
    }

    #[test]
    fn node_round_trips_through_json() {
        let node = Node::new(
            NodeId::new("n1"),
            NodeKind::DomainController,
            "DC01.corp.local",
            Provenance::manual(op(), 1_000),
        )
        .with_identity(IdentityKey::primary(
            IdentityKeyKind::Fqdn,
            "dc01.corp.local",
        ))
        .with_identity(IdentityKey::new(IdentityKeyKind::IpAddress, "10.0.0.1"));

        let json = serde_json::to_string(&node).unwrap();
        let back: Node = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
        assert!(back.kind.is_high_value());
        assert_eq!(back.identity_keys[0].index_token(), "Fqdn:dc01.corp.local");
    }

    #[test]
    fn compromise_level_orders_by_severity() {
        assert!(CompromiseLevel::DomainAdmin > CompromiseLevel::User);
        assert!(CompromiseLevel::User > CompromiseLevel::None);
    }

    #[test]
    fn edge_traversability_excludes_structural_edges() {
        assert!(EdgeKind::AdminTo.is_traversable());
        assert!(!EdgeKind::SameSegment.is_traversable());
    }

    #[test]
    fn source_serializes_with_tool_tag() {
        let s = Source::Import("bloodhound".into());
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(
            j,
            serde_json::json!({"kind": "import", "tool": "bloodhound"})
        );
    }
}
