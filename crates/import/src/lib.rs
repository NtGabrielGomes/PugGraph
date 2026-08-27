//! # import
//!
//! The scanner import pipeline (plan phase 3). It parses tool output and feeds
//! it through the campaign document's identity-key **reconciliation**, so the
//! same host seen by Nmap (IP) and later by other tools (SID, hostname)
//! collapses onto one node instead of duplicating — the low-friction-capture
//! invariant, automated. Services become nodes linked to their host by
//! `LISTENS_ON`, so exposure participates in attack-path reasoning.

pub mod bloodhound;
pub mod error;
pub mod nessus;
pub mod netexec;
pub mod nmap;

pub use bloodhound::{apply_bloodhound, parse as parse_bloodhound, BhType, BloodHoundFile};
pub use error::ImportError;
pub use nessus::{apply_nessus, parse as parse_nessus, NessusHost, NessusItem};
pub use netexec::{apply_netexec, parse as parse_netexec, NxcCred, NxcHost, NxcOutput};
pub use nmap::{parse as parse_nmap_hosts, ParsedHost, ParsedPort};

use crdt::{CampaignDoc, CrdtError};
use domain::{
    Confidence, Edge, EdgeId, EdgeKind, IdentityKey, IdentityKeyKind, NodeKind, OperatorId,
    Provenance, Source, Timestamp,
};

/// What an import run produced (records processed, not necessarily new — re-imports
/// reconcile onto existing nodes). `hosts`/`services` are Nmap-shaped counts;
/// `nodes`/`credentials` generalize to the AD and credential importers.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub hosts: usize,
    pub services: usize,
    pub edges: usize,
    pub nodes: usize,
    pub credentials: usize,
}

pub(crate) fn import_provenance(author: &OperatorId, now: Timestamp, tool: &str) -> Provenance {
    Provenance {
        author: author.clone(),
        source: Source::Import(tool.into()),
        confidence: Confidence::Confirmed,
        first_seen: now,
        last_verified: now,
    }
}

fn guess_kind(os: &Option<String>) -> NodeKind {
    host_kind_from_os(os.as_deref())
}

/// Map an OS string to a host node kind (shared by the importers).
pub(crate) fn host_kind_from_os(os: Option<&str>) -> NodeKind {
    match os.map(str::to_lowercase) {
        Some(s) if s.contains("windows") => NodeKind::HostWindows,
        Some(s) if s.contains("linux") => NodeKind::HostLinux,
        Some(s) if s.contains("mac os") || s.contains("macos") || s.contains("darwin") => {
            NodeKind::HostMacos
        }
        _ => NodeKind::HostWindows,
    }
}

/// Apply parsed Nmap hosts into the campaign document, reconciling against
/// existing nodes.
pub fn apply_nmap(
    doc: &CampaignDoc,
    hosts: &[ParsedHost],
    author: &OperatorId,
    now: Timestamp,
) -> Result<ImportSummary, CrdtError> {
    let prov = import_provenance(author, now, "nmap");
    let mut summary = ImportSummary::default();

    for h in hosts {
        let mut ikeys = Vec::new();
        if let Some(ip) = &h.ipv4 {
            ikeys.push(IdentityKey::primary(IdentityKeyKind::IpAddress, ip));
        }
        if let Some(mac) = &h.mac {
            ikeys.push(IdentityKey::new(IdentityKeyKind::MacAddress, mac));
        }
        for hn in &h.hostnames {
            ikeys.push(IdentityKey::new(IdentityKeyKind::Fqdn, hn.to_lowercase()));
        }
        if ikeys.is_empty() {
            continue;
        }

        let label = h
            .hostnames
            .first()
            .cloned()
            .or_else(|| h.ipv4.clone())
            .unwrap_or_else(|| "host".to_string());
        let host_id = doc.resolve_or_create(&ikeys, guess_kind(&h.os), &label, &prov)?;
        summary.hosts += 1;
        if let Some(os) = &h.os {
            doc.set_node_field(&host_id, "os_version", &serde_json::json!(os))?;
        }

        for p in &h.ports {
            if p.state != "open" {
                continue;
            }
            let svc_label = format!(
                "{}/{} {}",
                p.protocol,
                p.portid,
                p.service.clone().unwrap_or_default()
            );
            // Identity-scoped to the host so re-imports reconcile this service.
            let svc_key = IdentityKey::primary(
                IdentityKeyKind::Custom,
                format!("svc:{}:{}/{}", host_id, p.protocol, p.portid),
            );
            let svc_id =
                doc.resolve_or_create(&[svc_key], NodeKind::Service, svc_label.trim(), &prov)?;
            summary.services += 1;
            doc.set_node_field(&svc_id, "port", &serde_json::json!(p.portid))?;
            doc.set_node_field(&svc_id, "protocol", &serde_json::json!(p.protocol))?;
            if let Some(prod) = &p.product {
                doc.set_node_field(&svc_id, "product", &serde_json::json!(prod))?;
            }
            if let Some(ver) = &p.version {
                doc.set_node_field(&svc_id, "version", &serde_json::json!(ver))?;
            }

            let eid = EdgeId::new(format!("{}|listens_on|{}", host_id, svc_id));
            let mut edge = Edge::new(eid, EdgeKind::ListensOn, host_id.clone(), svc_id.clone(), prov.clone());
            edge.confidence = Confidence::Confirmed;
            doc.add_edge(&edge)?;
            summary.edges += 1;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests;
