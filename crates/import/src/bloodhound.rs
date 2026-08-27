//! BloodHound / SharpHound JSON importer.
//!
//! Parses a SharpHound collection (one JSON file per object type) into the
//! reconciled campaign graph. AD objects become typed nodes keyed by their
//! `objectid` (an `ad_sid` identity key) and, for computers/domains, their name
//! (an `fqdn`/`domain_name` key) — so a host already discovered by Nmap (by IP
//! or FQDN) collapses onto the *same* node instead of duplicating. Relationships
//! (group membership, ACL abuse, sessions, local admin, domain trusts) become
//! the same [`EdgeKind`]s BloodHound itself reasons over, so a shortest path to
//! Domain Admin is a shortest path in our graph.
//!
//! Tolerant by design: SharpHound's JSON casing has drifted across versions
//! (`ObjectIdentifier`/`objectid`, `Properties`/`properties`, PascalCase vs
//! lowercase relation arrays, `Sessions` as a bare array or `{ "Results": [..] }`),
//! so every field accepts the known aliases and anything unrecognized is skipped
//! rather than rejected. Parsing is pure and total: hostile input yields an
//! `Err`, never a panic — the same property the Nmap parser holds, so this is
//! equally safe to fuzz.

use crate::error::ImportError;
use crate::{import_provenance, ImportSummary};
use crdt::{CampaignDoc, CrdtError};
use domain::{
    Confidence, Edge, EdgeId, EdgeKind, IdentityKey, IdentityKeyKind, NodeId, NodeKind, OperatorId,
    Provenance, Timestamp,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// The object type of a SharpHound file, taken from its `meta.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BhType {
    Users,
    Computers,
    Groups,
    Domains,
    Gpos,
    Ous,
    Unknown,
}

impl BhType {
    fn from_meta(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "users" | "user" => BhType::Users,
            "computers" | "computer" => BhType::Computers,
            "groups" | "group" => BhType::Groups,
            "domains" | "domain" => BhType::Domains,
            "gpos" | "gpo" => BhType::Gpos,
            "ous" | "ou" => BhType::Ous,
            _ => BhType::Unknown,
        }
    }

    fn default_node_kind(self) -> NodeKind {
        match self {
            BhType::Users => NodeKind::UserAccount,
            BhType::Computers => NodeKind::HostWindows, // refined by OS in `node_kind`
            BhType::Groups => NodeKind::Group,
            BhType::Domains => NodeKind::Domain,
            BhType::Gpos => NodeKind::Gpo,
            BhType::Ous => NodeKind::OrganizationalUnit,
            BhType::Unknown => NodeKind::Custom,
        }
    }
}

/// A parsed SharpHound file: its object type plus the objects it carried.
#[derive(Debug)]
pub struct BloodHoundFile {
    pub object_type: BhType,
    objects: Vec<BhObject>,
}

/// Parse one SharpHound JSON file (e.g. `*_computers.json`).
pub fn parse(json: &str) -> Result<BloodHoundFile, ImportError> {
    let file: BhFile = serde_json::from_str(json).map_err(|e| ImportError::Parse(e.to_string()))?;
    Ok(BloodHoundFile {
        object_type: BhType::from_meta(&file.meta.kind),
        objects: file.data,
    })
}

/// Apply parsed SharpHound files into the campaign document. Files are processed
/// together (relationships cross files), reconciling against existing nodes.
pub fn apply_bloodhound(
    doc: &CampaignDoc,
    files: &[BloodHoundFile],
    author: &OperatorId,
    now: Timestamp,
) -> Result<ImportSummary, CrdtError> {
    let prov = import_provenance(author, now, "bloodhound");
    let mut summary = ImportSummary::default();
    // SID -> node id, so relationship endpoints in other files resolve precisely
    // (even when the same host already exists from Nmap, reconciled by FQDN).
    let mut by_sid: HashMap<String, NodeId> = HashMap::new();

    // Pass 1: create/reconcile every object as a node, indexing it by SID.
    for file in files {
        for obj in &file.objects {
            let Some(sid) = obj.sid() else { continue };
            let name = obj.display_name();
            let kind = obj.node_kind(file.object_type);

            let mut ikeys = vec![IdentityKey::primary(IdentityKeyKind::AdSid, sid.clone())];
            match file.object_type {
                BhType::Computers => {
                    if let Some(n) = &name {
                        ikeys.push(IdentityKey::new(IdentityKeyKind::Fqdn, n.to_lowercase()));
                    }
                }
                BhType::Domains => {
                    if let Some(n) = &name {
                        ikeys.push(IdentityKey::new(IdentityKeyKind::DomainName, n.to_lowercase()));
                    }
                }
                BhType::Users => {
                    if let Some(n) = &name {
                        if n.contains('@') {
                            ikeys.push(IdentityKey::new(IdentityKeyKind::AccountUpn, n.to_lowercase()));
                        }
                    }
                }
                _ => {}
            }

            let label = name.clone().unwrap_or_else(|| sid.clone());
            let node_id = doc.resolve_or_create(&ikeys, kind, &label, &prov)?;
            obj.write_fields(doc, &node_id, file.object_type)?;
            if by_sid.insert(sid.clone(), node_id).is_none() {
                summary.nodes += 1;
                if file.object_type == BhType::Computers {
                    summary.hosts += 1;
                }
            }
        }
    }

    // Pass 2: relationships. Endpoints resolve through the SID index; an endpoint
    // we never enumerated (e.g. a well-known SID) is skipped rather than faked.
    for file in files {
        for obj in &file.objects {
            let Some(sid) = obj.sid() else { continue };
            let Some(self_id) = by_sid.get(&sid).cloned() else { continue };

            // Group membership: each member --member_of--> this group.
            for m in &obj.members {
                if let Some(src) = m.object_identifier.as_ref().and_then(|s| by_sid.get(s).cloned()) {
                    add_edge(doc, &mut summary, EdgeKind::MemberOf, src, self_id.clone(), &prov)?;
                }
            }

            // ACL abuse: the principal --<right>--> this object.
            for ace in &obj.aces {
                if let (Some(psid), Some(right)) = (&ace.principal_sid, &ace.right_name) {
                    if let (Some(src), Some(kind)) = (by_sid.get(psid).cloned(), ace_edge_kind(right)) {
                        add_edge(doc, &mut summary, kind, src, self_id.clone(), &prov)?;
                    }
                }
            }

            // Domain trusts: this domain --trusts--> target (stub the target if unseen).
            for t in &obj.trusts {
                if let Some(tsid) = &t.target_domain_sid {
                    let tgt = match by_sid.get(tsid).cloned() {
                        Some(id) => id,
                        None => {
                            let mut ik = vec![IdentityKey::primary(IdentityKeyKind::AdSid, tsid.clone())];
                            let tlabel = t.target_domain_name.clone().unwrap_or_else(|| tsid.clone());
                            if let Some(dn) = &t.target_domain_name {
                                ik.push(IdentityKey::new(IdentityKeyKind::DomainName, dn.to_lowercase()));
                            }
                            let id = doc.resolve_or_create(&ik, NodeKind::Domain, &tlabel, &prov)?;
                            if by_sid.insert(tsid.clone(), id.clone()).is_none() {
                                summary.nodes += 1;
                            }
                            id
                        }
                    };
                    // Carry the trust semantics the cost model routes on (sid_filtering
                    // blocks SID-history abuse; direction/type/transitive for display).
                    let mut tf: Vec<(&'static str, Value)> = Vec::new();
                    if let Some(d) = &t.trust_direction {
                        tf.push(("direction", json!(trust_direction_label(d))));
                    }
                    if let Some(tt) = &t.trust_type {
                        tf.push(("trust_type", json!(tt)));
                    }
                    if let Some(tr) = t.is_transitive {
                        tf.push(("transitive", json!(tr)));
                    }
                    if let Some(sf) = t.sid_filtering_enabled {
                        tf.push(("sid_filtering", json!(sf)));
                    }
                    add_edge_with(doc, &mut summary, EdgeKind::Trusts, self_id.clone(), tgt, &prov, tf)?;
                }
            }

            // Sessions: computer --has_session--> user.
            for item in results_of(&obj.sessions) {
                let computer = str_field(&item, &["ComputerSID", "computersid"]);
                let user = str_field(&item, &["UserSID", "usersid"]);
                if let (Some(c), Some(u)) = (computer, user) {
                    if let (Some(cs), Some(us)) = (by_sid.get(c).cloned(), by_sid.get(u).cloned()) {
                        add_edge(doc, &mut summary, EdgeKind::HasSession, cs, us, &prov)?;
                    }
                }
            }

            // Local admins: principal --admin_to--> this computer.
            for item in results_of(&obj.local_admins) {
                if let Some(src) = str_field(&item, &["ObjectIdentifier", "objectid"])
                    .and_then(|p| by_sid.get(p).cloned())
                {
                    add_edge(doc, &mut summary, EdgeKind::AdminTo, src, self_id.clone(), &prov)?;
                }
            }
        }
    }

    Ok(summary)
}

/// Add a confirmed, deterministically-identified edge (so re-imports reconcile
/// instead of duplicating). Self-loops are dropped.
fn add_edge(
    doc: &CampaignDoc,
    summary: &mut ImportSummary,
    kind: EdgeKind,
    source: NodeId,
    target: NodeId,
    prov: &Provenance,
) -> Result<(), CrdtError> {
    add_edge_with(doc, summary, kind, source, target, prov, Vec::new())
}

/// Like [`add_edge`] but stamps typed attributes into the edge's `fields` bag (e.g.
/// trust direction / SID-filtering), so the attack-path cost model routes on the
/// real semantics instead of a bare edge kind.
fn add_edge_with(
    doc: &CampaignDoc,
    summary: &mut ImportSummary,
    kind: EdgeKind,
    source: NodeId,
    target: NodeId,
    prov: &Provenance,
    fields: Vec<(&'static str, Value)>,
) -> Result<(), CrdtError> {
    if source == target {
        return Ok(());
    }
    let eid = EdgeId::new(format!("{}|{:?}|{}", source, kind, target));
    let mut edge = Edge::new(eid, kind, source, target, prov.clone());
    edge.confidence = Confidence::Confirmed;
    for (k, v) in fields {
        edge.fields.insert(k.to_string(), v);
    }
    doc.add_edge(&edge)?;
    summary.edges += 1;
    Ok(())
}

/// Normalize a SharpHound `TrustDirection` (a 0..3 enum in newer captures, a string
/// in older ones) to a stable label.
fn trust_direction_label(v: &Value) -> &'static str {
    match v {
        Value::Number(n) => match n.as_i64() {
            Some(0) => "disabled",
            Some(1) => "inbound",
            Some(2) => "outbound",
            Some(3) => "bidirectional",
            _ => "unknown",
        },
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "disabled" => "disabled",
            "inbound" => "inbound",
            "outbound" => "outbound",
            "bidirectional" => "bidirectional",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

// Mirrored 1:1 in the web importer (web/src/io/import.ts `aceEdgeKind`); keep both
// in sync so the same SharpHound file yields the same graph on either side.
fn ace_edge_kind(right: &str) -> Option<EdgeKind> {
    match right.to_ascii_lowercase().as_str() {
        "genericall" => Some(EdgeKind::GenericAll),
        "genericwrite" => Some(EdgeKind::GenericWrite),
        "writedacl" => Some(EdgeKind::WriteDacl),
        "owns" | "owner" => Some(EdgeKind::Owns),
        "writeowner" | "writeownerlimitedrights" => Some(EdgeKind::WriteOwner),
        "allextendedrights" => Some(EdgeKind::AllExtendedRights),
        "forcechangepassword" => Some(EdgeKind::ForceChangePassword),
        "addmember" | "addmembers" => Some(EdgeKind::AddMember),
        "addself" => Some(EdgeKind::AddSelf),
        "addkeycredentiallink" | "writekeycredentiallink" => Some(EdgeKind::ShadowCredentials),
        "writespn" | "addspn" | "writeserviceprincipalname" => Some(EdgeKind::WriteSpn),
        "addallowedtoact" | "allowedtoact" | "writeaccountrestrictions" => {
            Some(EdgeKind::AllowedToAct)
        }
        "allowedtodelegate" => Some(EdgeKind::AllowedToDelegate),
        "readgmsapassword" => Some(EdgeKind::ReadGmsaPassword),
        "readlapspassword" | "synclapspassword" => Some(EdgeKind::ReadLapsPassword),
        "writegplink" => Some(EdgeKind::WriteGpLink),
        "dcsync" | "getchangesall" => Some(EdgeKind::DcSync),
        "manageca" | "managecertificates" => Some(EdgeKind::ManageCa),
        "coercetotgt" => Some(EdgeKind::Coerce),
        _ => None, // unmodeled rights are skipped, not misrepresented
    }
}

/// A relation array SharpHound encodes either as a bare array or as
/// `{ "Results": [...] }` (the shape drifted across versions).
fn results_of(v: &Value) -> Vec<Value> {
    if let Some(arr) = v.as_array() {
        arr.clone()
    } else if let Some(arr) = v.get("Results").and_then(Value::as_array) {
        arr.clone()
    } else {
        Vec::new()
    }
}

fn str_field<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_str))
}

// ---------------------------------------------------------------------------
// Tolerant deserialization model (aliases cover SharpHound's casing drift).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct BhFile {
    #[serde(default)]
    data: Vec<BhObject>,
    #[serde(default)]
    meta: BhMeta,
}

#[derive(Debug, Deserialize, Default)]
struct BhMeta {
    #[serde(default, rename = "type")]
    kind: String,
}

#[derive(Debug, Deserialize, Default)]
struct BhObject {
    #[serde(default, alias = "ObjectIdentifier")]
    objectid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, alias = "Properties")]
    properties: BhProps,
    #[serde(default, alias = "Members")]
    members: Vec<BhMember>,
    #[serde(default, alias = "Aces")]
    aces: Vec<BhAce>,
    #[serde(default, alias = "Trusts")]
    trusts: Vec<BhTrust>,
    #[serde(default, alias = "Sessions")]
    sessions: Value,
    #[serde(default, alias = "LocalAdmins")]
    local_admins: Value,
}

impl BhObject {
    fn sid(&self) -> Option<String> {
        self.objectid.clone().or_else(|| self.properties.objectid.clone())
    }

    fn display_name(&self) -> Option<String> {
        self.name.clone().or_else(|| self.properties.name.clone())
    }

    fn node_kind(&self, t: BhType) -> NodeKind {
        let p = &self.properties;
        match t {
            BhType::Computers => crate::host_kind_from_os(p.operatingsystem.as_deref()),
            // A SPN-bearing user IS a service account (and Kerberoastable).
            BhType::Users if p.hasspn == Some(true) || !p.serviceprincipalnames.is_empty() => {
                NodeKind::ServiceAccount
            }
            other => other.default_node_kind(),
        }
    }

    fn write_fields(&self, doc: &CampaignDoc, id: &NodeId, t: BhType) -> Result<(), CrdtError> {
        let p = &self.properties;
        if let Some(d) = &p.domain {
            doc.set_node_field(id, "domain", &json!(d))?;
        }
        match t {
            BhType::Computers => {
                if let Some(os) = &p.operatingsystem {
                    doc.set_node_field(id, "os_version", &json!(os))?;
                }
                if let Some(e) = p.enabled {
                    doc.set_node_field(id, "enabled", &json!(e))?;
                }
                if p.unconstraineddelegation == Some(true) {
                    doc.set_node_field(id, "unconstrained_delegation", &json!(true))?;
                }
            }
            BhType::Users => {
                if let Some(n) = self.display_name() {
                    doc.set_node_field(id, "upn", &json!(n))?;
                }
                if let Some(e) = p.enabled {
                    doc.set_node_field(id, "enabled", &json!(e))?;
                }
                if let Some(a) = p.admincount {
                    doc.set_node_field(id, "admin_count", &json!(a))?;
                }
                if p.hasspn == Some(true) || !p.serviceprincipalnames.is_empty() {
                    doc.set_node_field(id, "kerberoastable", &json!(true))?;
                    if !p.serviceprincipalnames.is_empty() {
                        doc.set_node_field(id, "spn", &json!(p.serviceprincipalnames))?;
                    }
                }
                if p.dontreqpreauth == Some(true) {
                    doc.set_node_field(id, "asrep_roastable", &json!(true))?;
                }
                if !p.sidhistory.is_empty() {
                    doc.set_node_field(id, "sid_history", &json!(p.sidhistory))?;
                }
            }
            _ => {}
        }
        if p.highvalue == Some(true) {
            doc.set_node_field(id, "is_tier_zero", &json!(true))?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Default)]
struct BhProps {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    objectid: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    operatingsystem: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    admincount: Option<bool>,
    // Abuse-surface properties the path engine reasons over (roast / delegation /
    // SID history / tier-0). Previously parsed-and-dropped; now persisted to fields.
    #[serde(default)]
    hasspn: Option<bool>,
    #[serde(default)]
    serviceprincipalnames: Vec<String>,
    #[serde(default)]
    dontreqpreauth: Option<bool>,
    #[serde(default)]
    unconstraineddelegation: Option<bool>,
    #[serde(default)]
    sidhistory: Vec<String>,
    #[serde(default)]
    highvalue: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct BhMember {
    #[serde(default, alias = "ObjectIdentifier", alias = "objectid")]
    object_identifier: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct BhAce {
    #[serde(default, alias = "PrincipalSID", alias = "principalsid")]
    principal_sid: Option<String>,
    #[serde(default, alias = "RightName", alias = "rightname")]
    right_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct BhTrust {
    #[serde(default, alias = "TargetDomainSid", alias = "targetdomainsid")]
    target_domain_sid: Option<String>,
    #[serde(default, alias = "TargetDomainName", alias = "targetdomainname")]
    target_domain_name: Option<String>,
    #[serde(default, alias = "TrustDirection", alias = "trustdirection")]
    trust_direction: Option<Value>,
    #[serde(default, alias = "TrustType", alias = "trusttype")]
    trust_type: Option<String>,
    #[serde(default, alias = "IsTransitive", alias = "istransitive")]
    is_transitive: Option<bool>,
    #[serde(default, alias = "SidFilteringEnabled", alias = "sidfilteringenabled")]
    sid_filtering_enabled: Option<bool>,
}
