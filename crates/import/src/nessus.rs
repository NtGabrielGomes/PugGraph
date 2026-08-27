//! Nessus (`.nessus` v2) importer.
//!
//! Parses a Nessus scan into the campaign graph: each `ReportHost` becomes a
//! host node (reconciled by IP/FQDN), each `ReportItem` with a port an exposed
//! `service` node linked by `listens_on`, and each non-informational item a
//! structured finding under the node's `fields["findings"]` — the same shape the
//! side panel and report consume. Total parsing: malformed XML errors; hostile
//! input never panics.

use crate::error::ImportError;
use crate::{import_provenance, ImportSummary};
use crdt::{CampaignDoc, CrdtError};
use domain::{
    Confidence, Edge, EdgeId, EdgeKind, IdentityKey, IdentityKeyKind, NodeId, NodeKind, OperatorId,
    Timestamp,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NessusItem {
    pub port: u16,
    pub protocol: String,
    pub svc_name: Option<String>,
    pub plugin_name: String,
    pub severity: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NessusHost {
    pub ip: Option<String>,
    pub fqdn: Option<String>,
    pub os: Option<String>,
    pub items: Vec<NessusItem>,
}

/// Parse a `.nessus` XML document into hosts and their report items.
pub fn parse(xml: &str) -> Result<Vec<NessusHost>, ImportError> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| ImportError::Parse(e.to_string()))?;
    let mut hosts = Vec::new();

    for rh in doc.descendants().filter(|n| n.has_tag_name("ReportHost")) {
        let mut host = NessusHost::default();
        if let Some(name) = rh.attribute("name") {
            host.ip = Some(name.to_string()); // often the IP; tags refine it
        }
        for tag in rh.descendants().filter(|n| n.has_tag_name("tag")) {
            match tag.attribute("name") {
                Some("host-ip") => host.ip = tag.text().map(str::to_string),
                Some("host-fqdn") => host.fqdn = tag.text().map(str::to_string),
                Some("operating-system") => host.os = tag.text().map(str::to_string),
                _ => {}
            }
        }
        for item in rh.children().filter(|n| n.has_tag_name("ReportItem")) {
            let port = item.attribute("port").and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            let protocol = item.attribute("protocol").unwrap_or("tcp").to_string();
            let svc_name = item
                .attribute("svc_name")
                .map(str::to_string)
                .filter(|s| s != "general" && !s.is_empty());
            let plugin_name = item.attribute("pluginName").unwrap_or("Nessus finding").to_string();
            let severity = item.attribute("severity").and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
            host.items.push(NessusItem { port, protocol, svc_name, plugin_name, severity });
        }
        hosts.push(host);
    }
    Ok(hosts)
}

/// Apply parsed Nessus hosts into the campaign document.
pub fn apply_nessus(
    doc: &CampaignDoc,
    hosts: &[NessusHost],
    author: &OperatorId,
    now: Timestamp,
) -> Result<ImportSummary, CrdtError> {
    let prov = import_provenance(author, now, "nessus");
    let mut summary = ImportSummary::default();

    for h in hosts {
        let mut ikeys = Vec::new();
        if let Some(ip) = &h.ip {
            ikeys.push(IdentityKey::primary(IdentityKeyKind::IpAddress, ip.clone()));
        }
        if let Some(fqdn) = &h.fqdn {
            ikeys.push(IdentityKey::new(IdentityKeyKind::Fqdn, fqdn.to_lowercase()));
        }
        if ikeys.is_empty() {
            continue;
        }
        let label = h.fqdn.clone().or_else(|| h.ip.clone()).unwrap_or_else(|| "host".into());
        let host_id = doc.resolve_or_create(&ikeys, guess_kind(h.os.as_deref()), &label, &prov)?;
        summary.hosts += 1;
        if let Some(os) = &h.os {
            doc.set_node_field(&host_id, "os_version", &json!(os))?;
        }

        let mut host_findings: Vec<Value> = Vec::new();
        for item in &h.items {
            if item.severity == 0 {
                continue; // skip purely informational items
            }
            let finding = json!({
                "title": item.plugin_name,
                "severity": severity_label(item.severity),
                "status": "open",
            });
            if item.port == 0 {
                host_findings.push(finding);
                continue;
            }
            let svc_key = IdentityKey::primary(
                IdentityKeyKind::Custom,
                format!("svc:{}:{}/{}", host_id, item.protocol, item.port),
            );
            let svc_label =
                format!("{}/{} {}", item.protocol, item.port, item.svc_name.clone().unwrap_or_default());
            let svc_id = doc.resolve_or_create(&[svc_key], NodeKind::Service, svc_label.trim(), &prov)?;
            summary.services += 1;
            doc.set_node_field(&svc_id, "port", &json!(item.port))?;
            doc.set_node_field(&svc_id, "protocol", &json!(item.protocol))?;
            if let Some(s) = &item.svc_name {
                doc.set_node_field(&svc_id, "product", &json!(s))?;
            }
            merge_findings(doc, &svc_id, vec![finding])?;

            let eid = EdgeId::new(format!("{}|listens_on|{}", host_id, svc_id));
            let mut edge = Edge::new(eid, EdgeKind::ListensOn, host_id.clone(), svc_id.clone(), prov.clone());
            edge.confidence = Confidence::Confirmed;
            doc.add_edge(&edge)?;
            summary.edges += 1;
        }
        if !host_findings.is_empty() {
            merge_findings(doc, &host_id, host_findings)?;
        }
    }

    Ok(summary)
}

/// Merge new findings into a node's `fields["findings"]`, de-duplicating by title
/// so re-imports (and manual findings) are preserved, not clobbered.
fn merge_findings(doc: &CampaignDoc, id: &NodeId, new: Vec<Value>) -> Result<(), CrdtError> {
    let mut all: Vec<Value> = Vec::new();
    let mut titles = std::collections::BTreeSet::new();
    if let Some(node) = doc.node(id)? {
        if let Some(Value::Array(existing)) = node.fields.get("findings") {
            for f in existing {
                if let Some(t) = f.get("title").and_then(Value::as_str) {
                    titles.insert(t.to_string());
                }
                all.push(f.clone());
            }
        }
    }
    for f in new {
        let t = f.get("title").and_then(Value::as_str).unwrap_or_default().to_string();
        if titles.insert(t) {
            all.push(f);
        }
    }
    doc.set_node_field(id, "findings", &Value::Array(all))
}

fn severity_label(sev: u8) -> &'static str {
    match sev {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info",
    }
}

fn guess_kind(os: Option<&str>) -> NodeKind {
    match os.map(|s| s.to_ascii_lowercase()) {
        Some(s) if s.contains("windows") => NodeKind::HostWindows,
        Some(s) if s.contains("linux") => NodeKind::HostLinux,
        Some(s) if s.contains("mac") || s.contains("darwin") => NodeKind::HostMacos,
        _ => NodeKind::HostWindows,
    }
}
