use super::*;
use domain::{CompromiseLevel, CredentialType, IdentityKey, IdentityKeyKind, NodeKind, Provenance};
use proptest::prelude::*;

fn prov() -> Provenance {
    Provenance::manual(OperatorId::new("op_test"), 1_000)
}

#[test]
fn node_round_trips_through_the_document() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let mut node = Node::new(
        NodeId::new("n1"),
        NodeKind::DomainController,
        "DC01",
        prov(),
    );
    node.compromise_level = CompromiseLevel::DomainAdmin;
    node.identity_keys.push(IdentityKey::primary(
        IdentityKeyKind::Fqdn,
        "dc01.corp.local",
    ));
    node.identity_keys
        .push(IdentityKey::new(IdentityKeyKind::IpAddress, "10.0.0.1"));
    node.fields.insert(
        "os_version".into(),
        serde_json::json!("Windows Server 2019"),
    );
    node.tags.insert("crown-jewel".into());
    doc.upsert_node(&node).unwrap();

    let got = doc.node(&NodeId::new("n1")).unwrap().unwrap();
    assert_eq!(got.kind, NodeKind::DomainController);
    assert_eq!(got.label, "DC01");
    assert_eq!(got.compromise_level, CompromiseLevel::DomainAdmin);
    assert_eq!(got.identity_keys.len(), 2);
    assert_eq!(
        got.fields.get("os_version").unwrap(),
        &serde_json::json!("Windows Server 2019")
    );
    assert!(got.tags.contains("crown-jewel"));
}

#[test]
fn identity_reconciliation_collapses_observations() {
    let doc = CampaignDoc::new("c1", 1).unwrap();

    let id1 = doc
        .resolve_or_create(
            &[IdentityKey::primary(IdentityKeyKind::IpAddress, "10.0.0.5")],
            NodeKind::HostWindows,
            "10.0.0.5",
            &prov(),
        )
        .unwrap();

    let id2 = doc
        .resolve_or_create(
            &[
                IdentityKey::new(IdentityKeyKind::IpAddress, "10.0.0.5"),
                IdentityKey::new(IdentityKeyKind::AdSid, "S-1-5-21-x"),
            ],
            NodeKind::HostWindows,
            "SRV05",
            &prov(),
        )
        .unwrap();
    assert_eq!(id1, id2);

    let id3 = doc
        .resolve_or_create(
            &[IdentityKey::primary(IdentityKeyKind::IpAddress, "10.0.0.6")],
            NodeKind::HostLinux,
            "10.0.0.6",
            &prov(),
        )
        .unwrap();
    assert_ne!(id1, id3);
    assert_eq!(doc.nodes().unwrap().len(), 2);
}

#[test]
fn edges_and_credentials_round_trip() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    doc.add_edge(&Edge::new(
        EdgeId::new("e1"),
        EdgeKind::AdminTo,
        NodeId::new("n1"),
        NodeId::new("n2"),
        prov(),
    ))
    .unwrap();
    let e = &doc.edges().unwrap()[0];
    assert_eq!(e.kind, EdgeKind::AdminTo);
    assert_eq!(e.source, NodeId::new("n1"));

    let cred = Credential {
        id: CredentialId::new("cr1"),
        username: "administrator".into(),
        domain: Some("CORP".into()),
        credential_type: CredentialType::PasswordNtlm,
        secret_sealed: Some("<sealed>".into()),
        belongs_to: Some(NodeId::new("n1")),
        obtained_from: Some(NodeId::new("n2")),
        validity: ValidityState::Valid,
        validity_as_of: 2_000,
        source: CredentialSource::Dump,
        tested_against: vec![],
        provenance: prov(),
    };
    doc.add_credential(&cred).unwrap();
    doc.add_test_result(
        &CredentialId::new("cr1"),
        &TestResult {
            host: NodeId::new("n2"),
            succeeded: true,
            at: 2_100,
            note: None,
        },
    )
    .unwrap();
    let got = &doc.credentials().unwrap()[0];
    assert_eq!(got.username, "administrator");
    assert_eq!(got.validity, ValidityState::Valid);
    assert_eq!(got.belongs_to, Some(NodeId::new("n1")));
    assert_eq!(got.obtained_from, Some(NodeId::new("n2")));
    assert_eq!(got.tested_against.len(), 1);
    assert!(got.tested_against[0].succeeded);

    doc.set_credential_links(&CredentialId::new("cr1"), Some(&NodeId::new("n3")), None)
        .unwrap();
    let got = &doc.credentials().unwrap()[0];
    assert_eq!(got.belongs_to, Some(NodeId::new("n3")));
    assert_eq!(got.obtained_from, None);
}

#[test]
fn event_chain_links_and_verifies() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let op = OperatorId::new("op_a");
    let e1 = doc
        .append_event(&op, "node.upsert", "added DC01", 10)
        .unwrap();
    let e2 = doc
        .append_event(&op, "cred.add", "dumped hash", 20)
        .unwrap();
    assert!(e1.prev_hash.is_empty());
    assert!(!e2.prev_hash.is_empty());
    assert!(doc.verify_event_chain().unwrap());
    let evs = doc.events().unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn concurrent_same_field_edit_converges_to_agreement() {
    let a = CampaignDoc::new("c1", 1).unwrap();
    let b = CampaignDoc::new("c1", 2).unwrap();
    for d in [&a, &b] {
        d.upsert_node(&Node::new(
            NodeId::new("n1"),
            NodeKind::HostLinux,
            "init",
            prov(),
        ))
        .unwrap();
    }
    a.set_label(&NodeId::new("n1"), "from-alice").unwrap();
    b.set_label(&NodeId::new("n1"), "from-bob").unwrap();

    let ua = a.export_all().unwrap();
    let ub = b.export_all().unwrap();
    a.import(&ub).unwrap();
    b.import(&ua).unwrap();

    let la = a.node(&NodeId::new("n1")).unwrap().unwrap().label;
    let lb = b.node(&NodeId::new("n1")).unwrap().unwrap().label;
    assert_eq!(la, lb);
    assert!(la == "from-alice" || la == "from-bob");
    assert_eq!(a.deep_value_json(), b.deep_value_json());
}

#[test]
fn snapshot_round_trips_unknown_roster_and_theme_containers() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    {
        let roster = doc.doc.get_map("roster");
        let bob = child_map(&roster, "op_bob").unwrap();
        bob.insert("display_name", "Bob").unwrap();
        bob.insert("role", "operator").unwrap();
        bob.insert("status", "active").unwrap();
        let theme = doc.doc.get_map("theme");
        theme.insert("color:host_windows", "#123456").unwrap();
        let messages = doc.doc.get_map("messages");
        let m1 = child_map(&messages, "m1").unwrap();
        m1.insert("author", "alice").unwrap();
        m1.insert("at", 10i64).unwrap();
        m1.insert("body", "pivoting via FS01").unwrap();
    }
    doc.commit();
    let snapshot = doc.export_snapshot().unwrap();

    let reloaded = CampaignDoc::from_snapshot("c1", 2, &snapshot).unwrap();
    let json = reloaded.deep_value_json();
    assert_eq!(
        json["roster"]["op_bob"]["display_name"],
        serde_json::json!("Bob")
    );
    assert_eq!(
        json["roster"]["op_bob"]["role"],
        serde_json::json!("operator")
    );
    assert_eq!(
        json["roster"]["op_bob"]["status"],
        serde_json::json!("active")
    );
    assert_eq!(
        json["theme"]["color:host_windows"],
        serde_json::json!("#123456")
    );
    assert_eq!(json["messages"]["m1"]["author"], serde_json::json!("alice"));
    assert_eq!(
        json["messages"]["m1"]["body"],
        serde_json::json!("pivoting via FS01")
    );

    assert!(reloaded.nodes().unwrap().is_empty());
}

#[derive(Clone, Debug)]
enum Op {
    AddNode(u8),
    SetLabel(u8, u8),
    AddTag(u8, u8),
    SetCompromise(u8, u8),
    AddEdge(u8, u8, u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..5).prop_map(Op::AddNode),
        (0u8..5, 0u8..6).prop_map(|(n, l)| Op::SetLabel(n, l)),
        (0u8..5, 0u8..4).prop_map(|(n, t)| Op::AddTag(n, t)),
        (0u8..5, 0u8..6).prop_map(|(n, c)| Op::SetCompromise(n, c)),
        (0u8..5, 0u8..5, 0u8..5).prop_map(|(e, s, t)| Op::AddEdge(e, s, t)),
    ]
}

fn apply(doc: &CampaignDoc, op: &Op) {
    let levels = [
        CompromiseLevel::Unknown,
        CompromiseLevel::None,
        CompromiseLevel::User,
        CompromiseLevel::Admin,
        CompromiseLevel::System,
        CompromiseLevel::DomainAdmin,
    ];
    match *op {
        Op::AddNode(n) => {
            let id = NodeId::new(format!("n{n}"));
            doc.upsert_node(&Node::new(
                id,
                NodeKind::HostWindows,
                format!("host{n}"),
                prov(),
            ))
            .unwrap();
        }
        Op::SetLabel(n, l) => doc
            .set_label(&NodeId::new(format!("n{n}")), &format!("L{l}"))
            .unwrap(),
        Op::AddTag(n, t) => doc
            .add_tag(&NodeId::new(format!("n{n}")), &format!("t{t}"))
            .unwrap(),
        Op::SetCompromise(n, c) => doc
            .set_compromise(&NodeId::new(format!("n{n}")), levels[c as usize])
            .unwrap(),
        Op::AddEdge(e, s, t) => doc
            .add_edge(&Edge::new(
                EdgeId::new(format!("e{e}")),
                EdgeKind::ConnectsTo,
                NodeId::new(format!("n{s}")),
                NodeId::new(format!("n{t}")),
                prov(),
            ))
            .unwrap(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(80))]

    #[test]
    fn replicas_converge_after_exchange(ops in proptest::collection::vec(op_strategy(), 0..40)) {
        let a = CampaignDoc::new("c1", 1).unwrap();
        let b = CampaignDoc::new("c1", 2).unwrap();
        for (i, op) in ops.iter().enumerate() {
            apply(if i % 2 == 0 { &a } else { &b }, op);
        }
        let ua = a.export_all().unwrap();
        let ub = b.export_all().unwrap();
        a.import(&ub).unwrap();
        b.import(&ua).unwrap();
        prop_assert_eq!(a.deep_value_json(), b.deep_value_json());
    }
}
