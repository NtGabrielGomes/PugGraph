use super::*;
use crdt::CampaignDoc;
use domain::{EdgeKind, NodeKind, OperatorId};

const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <address addr="00:0c:29:aa:bb:cc" addrtype="mac"/>
    <hostnames><hostname name="DC01.corp.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows" version="2019"/></port>
      <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos-sec"/></port>
      <port protocol="tcp" portid="139"><state state="closed"/><service name="netbios-ssn"/></port>
    </ports>
    <os><osmatch name="Microsoft Windows Server 2019"/></os>
  </host>
</nmaprun>"#;

#[test]
fn parses_hosts_ports_and_os() {
    let hosts = parse_nmap_hosts(SAMPLE).unwrap();
    assert_eq!(hosts.len(), 1);
    let h = &hosts[0];
    assert_eq!(h.ipv4.as_deref(), Some("10.0.0.1"));
    assert_eq!(h.mac.as_deref(), Some("00:0c:29:aa:bb:cc"));
    assert_eq!(h.hostnames, vec!["DC01.corp.local"]);
    assert!(h.os.as_deref().unwrap().contains("Windows Server 2019"));
    assert_eq!(h.ports.len(), 3);
    let open: Vec<u16> = h.ports.iter().filter(|p| p.state == "open").map(|p| p.portid).collect();
    assert_eq!(open, vec![445, 88]);
}

#[test]
fn applies_into_graph_with_reconciliation() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let author = OperatorId::new("op_importer");
    let hosts = parse_nmap_hosts(SAMPLE).unwrap();

    let summary = apply_nmap(&doc, &hosts, &author, 1000).unwrap();
    assert_eq!(summary.hosts, 1);
    assert_eq!(summary.services, 2); // only the two OPEN ports
    assert_eq!(summary.edges, 2);

    // 1 host + 2 service nodes; a LISTENS_ON edge per service.
    assert_eq!(doc.nodes().unwrap().len(), 3);
    let host = doc.nodes().unwrap().into_iter().find(|n| n.kind == NodeKind::DomainController || n.kind == NodeKind::HostWindows).unwrap();
    assert_eq!(host.kind, NodeKind::HostWindows);
    assert_eq!(host.fields.get("os_version").unwrap(), &serde_json::json!("Microsoft Windows Server 2019"));
    assert_eq!(doc.edges().unwrap().len(), 2);

    // Re-importing the same scan must reconcile, not duplicate.
    apply_nmap(&doc, &hosts, &author, 2000).unwrap();
    assert_eq!(doc.nodes().unwrap().len(), 3, "re-import must not create duplicate nodes");
    assert_eq!(doc.edges().unwrap().len(), 2, "re-import must not create duplicate edges");
}

#[test]
fn malformed_xml_is_an_error_not_a_panic() {
    assert!(parse_nmap_hosts("<nmaprun><host>").is_err());
    assert!(parse_nmap_hosts("definitely not xml").is_err());
}

#[test]
fn hostile_inputs_never_panic() {
    // Total parsing: any bytes either parse or error, but never crash.
    for input in ["", "\0\0\0", "<", "<a/>", "<nmaprun></nmaprun>", "<host><port portid=\"99999999\"/></host>", &"<host/>".repeat(500)] {
        let _ = parse_nmap_hosts(input); // must not panic
    }
    // An out-of-range port id is simply skipped, not fatal.
    let hosts = parse_nmap_hosts(r#"<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host></nmaprun>"#).unwrap();
    assert_eq!(hosts[0].ports.len(), 0);
}

// ---- BloodHound / SharpHound -----------------------------------------------

const BH_DOMAINS: &str = r#"{"meta":{"type":"domains","count":1},"data":[
  {"objectid":"S-1-5-21-DOMAIN","name":"CORP.LOCAL","properties":{"name":"CORP.LOCAL","domain":"CORP.LOCAL"},
   "Trusts":[{"TargetDomainSid":"S-1-5-21-PARTNER","TargetDomainName":"PARTNER.LOCAL","TrustDirection":"Inbound","TrustType":"External"}]}
]}"#;

const BH_COMPUTERS: &str = r#"{"meta":{"type":"computers","count":1},"data":[
  {"objectid":"S-1-5-21-DOMAIN-1001","name":"DC01.CORP.LOCAL",
   "properties":{"name":"DC01.CORP.LOCAL","operatingsystem":"Windows Server 2019","domain":"CORP.LOCAL","enabled":true},
   "LocalAdmins":{"Results":[{"ObjectIdentifier":"S-1-5-21-DOMAIN-512","ObjectType":"Group"}]},
   "Sessions":{"Results":[{"ComputerSID":"S-1-5-21-DOMAIN-1001","UserSID":"S-1-5-21-DOMAIN-1105"}]}}
]}"#;

const BH_USERS: &str = r#"{"meta":{"type":"users","count":1},"data":[
  {"objectid":"S-1-5-21-DOMAIN-1105","name":"JDOE@CORP.LOCAL",
   "properties":{"name":"JDOE@CORP.LOCAL","enabled":true,"admincount":false,"domain":"CORP.LOCAL"},
   "Aces":[{"PrincipalSID":"S-1-5-21-DOMAIN-512","PrincipalType":"Group","RightName":"GenericAll","IsInherited":false}]}
]}"#;

const BH_GROUPS: &str = r#"{"meta":{"type":"groups","count":1},"data":[
  {"objectid":"S-1-5-21-DOMAIN-512","name":"DOMAIN ADMINS@CORP.LOCAL",
   "properties":{"name":"DOMAIN ADMINS@CORP.LOCAL","domain":"CORP.LOCAL"},
   "Members":[{"ObjectIdentifier":"S-1-5-21-DOMAIN-1105","ObjectType":"User"}]}
]}"#;

fn bh_files() -> Vec<BloodHoundFile> {
    vec![
        parse_bloodhound(BH_DOMAINS).unwrap(),
        parse_bloodhound(BH_COMPUTERS).unwrap(),
        parse_bloodhound(BH_USERS).unwrap(),
        parse_bloodhound(BH_GROUPS).unwrap(),
    ]
}

#[test]
fn bloodhound_builds_the_ad_graph_with_canonical_edges() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let author = OperatorId::new("op_importer");

    let summary = apply_bloodhound(&doc, &bh_files(), &author, 1000).unwrap();

    // domain + computer + user + group + the stubbed trust-target domain = 5 nodes.
    assert_eq!(doc.nodes().unwrap().len(), 5);
    assert_eq!(summary.nodes, 5);

    // Five canonical BloodHound edges, one of each kind.
    let edges = doc.edges().unwrap();
    assert_eq!(summary.edges, 5);
    assert_eq!(edges.len(), 5);
    let kinds: std::collections::HashSet<_> = edges.iter().map(|e| e.kind).collect();
    for k in [EdgeKind::MemberOf, EdgeKind::GenericAll, EdgeKind::Trusts, EdgeKind::HasSession, EdgeKind::AdminTo] {
        assert!(kinds.contains(&k), "missing {k:?}");
    }

    // The computer is typed by its OS and carries structured fields.
    let dc = doc.nodes().unwrap().into_iter().find(|n| n.label.contains("DC01")).unwrap();
    assert_eq!(dc.kind, NodeKind::HostWindows);
    assert_eq!(dc.fields.get("os_version").unwrap(), &serde_json::json!("Windows Server 2019"));
}

#[test]
fn bloodhound_reconciles_onto_an_nmap_host_and_is_idempotent() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let author = OperatorId::new("op_importer");

    // Nmap saw DC01 first (by FQDN). BloodHound's computer must collapse onto it.
    let nmap = parse_nmap_hosts(
        r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><hostnames><hostname name="DC01.corp.local"/></hostnames></host></nmaprun>"#,
    )
    .unwrap();
    apply_nmap(&doc, &nmap, &author, 1000).unwrap();
    let before = doc.nodes().unwrap().len(); // 1: the DC host

    apply_bloodhound(&doc, &bh_files(), &author, 2000).unwrap();
    let nodes = doc.nodes().unwrap();
    let dc_nodes: Vec<_> = nodes.iter().filter(|n| n.label.to_lowercase().contains("dc01")).collect();
    assert_eq!(dc_nodes.len(), 1, "the BloodHound computer must reconcile onto the Nmap host");
    // domain + user + group + partner-trust-stub = 4 genuinely new nodes.
    assert_eq!(nodes.len(), before + 4);

    let node_count = nodes.len();
    let edge_count = doc.edges().unwrap().len();
    // Re-importing reconciles, never duplicates.
    apply_bloodhound(&doc, &bh_files(), &author, 3000).unwrap();
    assert_eq!(doc.nodes().unwrap().len(), node_count, "re-import must not duplicate nodes");
    assert_eq!(doc.edges().unwrap().len(), edge_count, "re-import must not duplicate edges");
}

#[test]
fn bloodhound_parsing_is_total_on_hostile_input() {
    for input in ["", "{}", "not json", "{\"data\":[]}", "{\"data\":[{}]}", r#"{"meta":{"type":"users"},"data":[{"objectid":"S-1"}]}"#] {
        let _ = parse_bloodhound(input); // must not panic; malformed JSON returns Err
    }
    // A file with an unknown type still parses; its objects map to Custom nodes.
    let f = parse_bloodhound(r#"{"meta":{"type":"weird"},"data":[{"objectid":"S-9","name":"x"}]}"#).unwrap();
    assert_eq!(f.object_type, BhType::Unknown);
}

// ---- NetExec / CrackMapExec ------------------------------------------------

const NXC_OUTPUT: &str = "\
SMB  10.0.0.1  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:CORP.LOCAL)
SMB  10.0.0.1  445  DC01  [+] CORP.LOCAL\\administrator:Passw0rd! (Pwn3d!)
SMB  10.0.0.2  445  WS01  [*] Windows 10 (name:WS01) (domain:CORP.LOCAL)
SMB  10.0.0.2  445  WS01  [-] CORP.LOCAL\\guest:badpass STATUS_LOGON_FAILURE
SMB  10.0.0.2  445  WS01  [+] CORP.LOCAL\\administrator:Passw0rd!
[*] an unrelated banner line that must be ignored
";

#[test]
fn netexec_parses_hosts_and_credentials() {
    let out = parse_netexec(NXC_OUTPUT).unwrap();
    assert_eq!(out.hosts.len(), 2);
    let dc = out.hosts.iter().find(|h| h.ip == "10.0.0.1").unwrap();
    assert_eq!(dc.hostname.as_deref(), Some("DC01"));
    assert!(dc.os.as_deref().unwrap().contains("Windows Server 2019"));
    // admin@DC (Pwn3d), guest@WS (failed), admin@WS (ok) = 3 cred lines.
    assert_eq!(out.creds.len(), 3);
    let pwn = out.creds.iter().find(|c| c.admin && c.success).unwrap();
    assert_eq!(pwn.username, "administrator");
    assert_eq!(pwn.domain.as_deref(), Some("CORP.LOCAL"));
}

#[test]
fn netexec_applies_compromise_and_aggregated_credentials() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let author = OperatorId::new("op");
    let out = parse_netexec(NXC_OUTPUT).unwrap();
    let summary = apply_netexec(&doc, &out, &author, 1000).unwrap();

    assert_eq!(summary.hosts, 2);
    assert_eq!(doc.nodes().unwrap().len(), 2);
    // DC01 is admin-compromised by the (Pwn3d!) result.
    let dc = doc.nodes().unwrap().into_iter().find(|n| n.label == "DC01").unwrap();
    assert_eq!(dc.compromise_level, domain::CompromiseLevel::Admin);

    // administrator opened both hosts -> one aggregated vault record; guest -> one.
    let creds = doc.credentials().unwrap();
    assert_eq!(creds.len(), 2);
    let admin = creds.iter().find(|c| c.username == "administrator").unwrap();
    assert_eq!(admin.validity, domain::ValidityState::Valid);
    assert_eq!(admin.tested_against.iter().filter(|t| t.succeeded).count(), 2);

    // Idempotent re-import.
    apply_netexec(&doc, &out, &author, 2000).unwrap();
    assert_eq!(doc.nodes().unwrap().len(), 2);
    assert_eq!(doc.credentials().unwrap().len(), 2);
}

#[test]
fn netexec_parsing_is_total_on_hostile_input() {
    for input in ["", "\0\0", "SMB", "garbage\nlines", "SMB x y z [+] :::", &"A B C D [+] x\\y:z\n".repeat(200)] {
        let _ = parse_netexec(input); // never panics
    }
}

// ---- Nessus ----------------------------------------------------------------

const NESSUS_XML: &str = r#"<?xml version="1.0"?>
<NessusClientData_v2><Report name="scan">
  <ReportHost name="10.0.0.1">
    <HostProperties>
      <tag name="host-ip">10.0.0.1</tag>
      <tag name="host-fqdn">dc01.corp.local</tag>
      <tag name="operating-system">Microsoft Windows Server 2019</tag>
    </HostProperties>
    <ReportItem port="445" svc_name="cifs" protocol="tcp" severity="4" pluginID="1" pluginName="MS17-010"></ReportItem>
    <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="2" pluginID="2" pluginName="RDP weak crypto"></ReportItem>
    <ReportItem port="0" protocol="tcp" severity="0" pluginID="3" pluginName="Nessus Scan Info"></ReportItem>
  </ReportHost>
</Report></NessusClientData_v2>"#;

#[test]
fn nessus_parses_hosts_items_and_os() {
    let hosts = parse_nessus(NESSUS_XML).unwrap();
    assert_eq!(hosts.len(), 1);
    let h = &hosts[0];
    assert_eq!(h.ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(h.fqdn.as_deref(), Some("dc01.corp.local"));
    assert!(h.os.as_deref().unwrap().contains("2019"));
    assert_eq!(h.items.len(), 3);
}

#[test]
fn nessus_applies_services_and_findings_and_reconciles() {
    let doc = CampaignDoc::new("c1", 1).unwrap();
    let author = OperatorId::new("op");

    // Nmap saw the host by FQDN first; Nessus must reconcile onto it.
    let nmap = parse_nmap_hosts(
        r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><hostnames><hostname name="dc01.corp.local"/></hostnames></host></nmaprun>"#,
    )
    .unwrap();
    apply_nmap(&doc, &nmap, &author, 500).unwrap();
    let before = doc.nodes().unwrap().len(); // 1 host

    let hosts = parse_nessus(NESSUS_XML).unwrap();
    let summary = apply_nessus(&doc, &hosts, &author, 1000).unwrap();
    assert_eq!(summary.hosts, 1);
    assert_eq!(summary.services, 2); // 445 + 3389 (the port-0 / severity-0 item is skipped)
    assert_eq!(summary.edges, 2);
    // Host reconciled (no duplicate) + 2 new service nodes.
    assert_eq!(doc.nodes().unwrap().len(), before + 2);

    // The critical finding is a structured finding on the service node.
    let svc = doc
        .nodes()
        .unwrap()
        .into_iter()
        .find(|n| n.kind == NodeKind::Service && n.fields.get("port") == Some(&serde_json::json!(445)))
        .unwrap();
    let findings = svc.fields.get("findings").and_then(|v| v.as_array()).unwrap();
    assert!(findings
        .iter()
        .any(|f| f["title"] == serde_json::json!("MS17-010") && f["severity"] == serde_json::json!("critical")));

    // Idempotent (findings de-dup by title; nodes reconcile).
    apply_nessus(&doc, &hosts, &author, 2000).unwrap();
    assert_eq!(doc.nodes().unwrap().len(), before + 2);
    let svc2 = doc.nodes().unwrap().into_iter().find(|n| n.kind == NodeKind::Service && n.fields.get("port") == Some(&serde_json::json!(445))).unwrap();
    assert_eq!(svc2.fields.get("findings").and_then(|v| v.as_array()).unwrap().len(), 1);
}

#[test]
fn nessus_parsing_is_total_on_hostile_input() {
    assert!(parse_nessus("not xml").is_err());
    for input in ["", "<x/>", "<ReportHost/>", "<NessusClientData_v2><Report><ReportHost name='h'><ReportItem/></ReportHost></Report></NessusClientData_v2>"] {
        let _ = parse_nessus(input); // never panics
    }
}
