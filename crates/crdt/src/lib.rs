pub mod error;
mod value;

pub use error::CrdtError;

use domain::{CompromiseLevel, CredentialId, EdgeId, NodeId, OperatorId, Timestamp};
use domain::{
    Confidence, Credential, CredentialSource, CredentialType, Edge, EdgeKind, Event, IdentityKey,
    Node, NodeKind, Provenance, Source, TestResult, ValidityState,
};
use loro::{ExportMode, LoroDoc, LoroMap, VersionVector};
use serde_json::json;
use ulid::Ulid;
use value::{child_list, child_map, deep_array, deep_object, enum_str, from_json, get_str};

pub struct CampaignDoc {
    doc: LoroDoc,
    campaign_id: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn write_prov(m: &LoroMap, p: &Provenance) -> Result<(), CrdtError> {
    m.insert("_author", p.author.as_str())?;
    m.insert("_confidence", enum_str(&p.confidence).as_str())?;
    m.insert("_source", serde_json::to_string(&p.source)?.as_str())?;
    m.insert("_first_seen", p.first_seen)?;
    m.insert("_last_verified", p.last_verified)?;
    Ok(())
}

fn read_prov(o: &serde_json::Map<String, serde_json::Value>) -> Provenance {
    let author = OperatorId::new(o.get("_author").and_then(|v| v.as_str()).unwrap_or(""));
    let confidence = o
        .get("_confidence")
        .and_then(|v| v.as_str())
        .and_then(|s| from_json::<Confidence>(json!(s)).ok())
        .unwrap_or_default();
    let source = o
        .get("_source")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<Source>(s).ok())
        .unwrap_or_default();
    
    Provenance {
        author,
        source,
        confidence,
        first_seen: o.get("_first_seen").and_then(|v| v.as_i64()).unwrap_or(0),
        last_verified: o
            .get("_last_verified")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
    }
}

impl CampaignDoc {
    pub fn new(campaign_id: &str, peer_id: u64) -> Result<Self, CrdtError> {
        let doc = LoroDoc::new();
        doc.set_peer_id(peer_id)?;
        doc.get_map("meta").insert("campaign_id", campaign_id)?;

        let _ = doc.get_map("nodes");
        let _ = doc.get_map("edges");
        let _ = doc.get_map("credentials");
        let _ = doc.get_map("idindex");
        let _ = doc.get_list("events");
        doc.commit();
        
        Ok(Self {
            doc,
            campaign_id: campaign_id.to_owned(),
        })
    }

    pub fn from_snapshot(
        campaign_id: &str,
        peer_id: u64,
        snapshot: &[u8],
    ) -> Result<Self, CrdtError> {
        let doc = LoroDoc::new();
        doc.set_peer_id(peer_id)?;
        doc.import(snapshot)?;
        
        Ok(Self {
            doc,
            campaign_id: campaign_id.to_owned(),
        })
    }

    pub fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    pub fn peer_id(&self) -> u64 {
        self.doc.peer_id()
    }

    pub fn upsert_node(&self, node: &Node) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), node.id.as_str())?;
        m.insert("kind", enum_str(&node.kind).as_str())?;
        m.insert("label", node.label.as_str())?;
        m.insert("compromise", enum_str(&node.compromise_level).as_str())?;
        write_prov(&m, &node.provenance)?;

        let idmap = child_map(&m, "identity")?;
        let idindex = self.doc.get_map("idindex");
        for k in &node.identity_keys {
            idmap.insert(k.index_token().as_str(), serde_json::to_string(k)?.as_str())?;
            idindex.insert(k.index_token().as_str(), node.id.as_str())?;
        }

        let fields = child_map(&m, "fields")?;
        for (key, val) in &node.fields {
            fields.insert(key.as_str(), serde_json::to_string(val)?.as_str())?;
        }

        let tags = child_map(&m, "tags")?;
        for t in &node.tags {
            tags.insert(t.as_str(), true)?;
        }
        Ok(())
    }

    pub fn set_node_field(
        &self,
        id: &NodeId,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), id.as_str())?;
        let fields = child_map(&m, "fields")?;
        fields.insert(key, serde_json::to_string(value)?.as_str())?;
        
        Ok(())
    }

    pub fn set_label(&self, id: &NodeId, label: &str) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), id.as_str())?;
        m.insert("label", label)?;
        
        Ok(())
    }

    pub fn set_compromise(&self, id: &NodeId, level: CompromiseLevel) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), id.as_str())?;
        m.insert("compromise", enum_str(&level).as_str())?;
        
        Ok(())
    }

    pub fn add_tag(&self, id: &NodeId, tag: &str) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), id.as_str())?;
        child_map(&m, "tags")?.insert(tag, true)?;
        
        Ok(())
    }

    pub fn remove_tag(&self, id: &NodeId, tag: &str) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("nodes"), id.as_str())?;
        child_map(&m, "tags")?.delete(tag)?;
        
        Ok(())
    }

    pub fn add_edge(&self, edge: &Edge) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("edges"), edge.id.as_str())?;
        m.insert("kind", enum_str(&edge.kind).as_str())?;
        m.insert("source", edge.source.as_str())?;
        m.insert("target", edge.target.as_str())?;
        m.insert("confidence", enum_str(&edge.confidence).as_str())?;
        write_prov(&m, &edge.provenance)?;
        
        let fields = child_map(&m, "fields")?;
        for (k, v) in &edge.fields {
            fields.insert(k.as_str(), serde_json::to_string(v)?.as_str())?;
        }
        
        let ev = child_map(&m, "evidence")?;
        for e in &edge.evidence {
            ev.insert(e.as_str(), true)?;
        }
        
        Ok(())
    }

    pub fn add_credential(&self, c: &Credential) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("credentials"), c.id.as_str())?;
        m.insert("username", c.username.as_str())?;
        if let Some(d) = &c.domain {
            m.insert("domain", d.as_str())?;
        }
        m.insert("credential_type", enum_str(&c.credential_type).as_str())?;
        m.insert("validity", enum_str(&c.validity).as_str())?;
        m.insert("validity_as_of", c.validity_as_of)?;
        m.insert("source", enum_str(&c.source).as_str())?;
        if let Some(s) = &c.secret_sealed {
            m.insert("secret_sealed", s.as_str())?;
        }
        if let Some(n) = &c.belongs_to {
            m.insert("belongs_to", n.as_str())?;
        }
        if let Some(n) = &c.obtained_from {
            m.insert("obtained_from", n.as_str())?;
        }
        write_prov(&m, &c.provenance)?;
        let tlist = child_list(&m, "tested_against")?;
        for t in &c.tested_against {
            tlist.push(serde_json::to_string(t)?.as_str())?;
        }
        
        Ok(())
    }

    pub fn set_credential_validity(
        &self,
        id: &CredentialId,
        validity: ValidityState,
        as_of: Timestamp,
    ) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("credentials"), id.as_str())?;
        m.insert("validity", enum_str(&validity).as_str())?;
        m.insert("validity_as_of", as_of)?;
        
        Ok(())
    }

    pub fn set_credential_links(
        &self,
        id: &CredentialId,
        belongs_to: Option<&NodeId>,
        obtained_from: Option<&NodeId>,
    ) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("credentials"), id.as_str())?;
        match belongs_to {
            Some(n) => m.insert("belongs_to", n.as_str())?,
            None => m.delete("belongs_to")?,
        }
        match obtained_from {
            Some(n) => m.insert("obtained_from", n.as_str())?,
            None => m.delete("obtained_from")?,
        }
        
        Ok(())
    }

    pub fn add_test_result(&self, id: &CredentialId, result: &TestResult) -> Result<(), CrdtError> {
        let m = child_map(&self.doc.get_map("credentials"), id.as_str())?;
        child_list(&m, "tested_against")?.push(serde_json::to_string(result)?.as_str())?;
        
        Ok(())
    }

    pub fn append_event(
        &self,
        author: &OperatorId,
        action: &str,
        summary: &str,
        now: Timestamp,
    ) -> Result<Event, CrdtError> {
        let existing = self.events()?;
        let prev_hash = match existing.last() {
            Some(e) => sha256_hex(&serde_json::to_vec(e)?),
            None => String::new(),
        };
        let event = Event {
            id: Ulid::new().to_string(),
            author: author.clone(),
            at: now,
            action: action.to_owned(),
            summary: summary.to_owned(),
            prev_hash,
        };
        self.doc
            .get_list("events")
            .push(serde_json::to_string(&event)?.as_str())?;
        
        Ok(event)
    }

    pub fn resolve_or_create(
        &self,
        identity_keys: &[IdentityKey],
        kind: NodeKind,
        label: &str,
        prov: &Provenance,
    ) -> Result<NodeId, CrdtError> {
        let idindex = self.doc.get_map("idindex");
        for k in identity_keys {
            if let Some(existing) = get_str(&idindex, &k.index_token()) {
                return Ok(NodeId::new(existing));
            }
        }
        
        let id = NodeId::new(Ulid::new().to_string());
        
        let mut node = Node::new(id.clone(), kind, label, prov.clone());
        node.identity_keys = identity_keys.to_vec();
        self.upsert_node(&node)?;
        
        Ok(id)
    }

    pub fn nodes(&self) -> Result<Vec<Node>, CrdtError> {
        let mut out = Vec::new();
        for (id, v) in deep_object(&self.doc.get_map("nodes"))? {
            if let serde_json::Value::Object(o) = v {
                if let Some(n) = parse_node(&id, &o) {
                    out.push(n);
                }
            }
        }
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        
        Ok(out)
    }

    pub fn node(&self, id: &NodeId) -> Result<Option<Node>, CrdtError> {
        Ok(self.nodes()?.into_iter().find(|n| &n.id == id))
    }

    pub fn edges(&self) -> Result<Vec<Edge>, CrdtError> {
        let mut out = Vec::new();
        for (id, v) in deep_object(&self.doc.get_map("edges"))? {
            if let serde_json::Value::Object(o) = v {
                if let Some(e) = parse_edge(&id, &o) {
                    out.push(e);
                }
            }
        }
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        
        Ok(out)
    }

    pub fn credentials(&self) -> Result<Vec<Credential>, CrdtError> {
        let mut out = Vec::new();
        for (id, v) in deep_object(&self.doc.get_map("credentials"))? {
            if let serde_json::Value::Object(o) = v {
                if let Some(c) = parse_credential(&id, &o) {
                    out.push(c);
                }
            }
        }
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        
        Ok(out)
    }

    pub fn events(&self) -> Result<Vec<Event>, CrdtError> {
        let mut out = Vec::new();
        for v in deep_array(&self.doc.get_list("events"))? {
            if let Some(s) = v.as_str() {
                if let Ok(e) = serde_json::from_str::<Event>(s) {
                    out.push(e);
                }
            }
        }
        
        Ok(out)
    }

    pub fn verify_event_chain(&self) -> Result<bool, CrdtError> {
        let events = self.events()?;
        let mut hashes = std::collections::HashSet::new();
        
        for e in &events {
            hashes.insert(sha256_hex(&serde_json::to_vec(e)?));
        }
        
        for e in &events {
            if !e.prev_hash.is_empty() && !hashes.contains(&e.prev_hash) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    pub fn commit(&self) {
        self.doc.commit();
    }

    pub fn version(&self) -> VersionVector {
        self.doc.oplog_vv()
    }

    pub fn export_snapshot(&self) -> Result<Vec<u8>, CrdtError> {
        self.doc.commit();
        Ok(self.doc.export(ExportMode::Snapshot)?)
    }

    pub fn export_updates_since(&self, since: &VersionVector) -> Result<Vec<u8>, CrdtError> {
        self.doc.commit();
        Ok(self.doc.export(ExportMode::updates(since))?)
    }

    pub fn export_all(&self) -> Result<Vec<u8>, CrdtError> {
        self.doc.commit();
        Ok(self
            .doc
            .export(ExportMode::updates(&VersionVector::default()))?)
    }

    pub fn import(&self, bytes: &[u8]) -> Result<(), CrdtError> {
        self.doc.import(bytes)?;
        Ok(())
    }

    pub fn deep_value_json(&self) -> serde_json::Value {
        self.doc.commit();
        serde_json::to_value(self.doc.get_deep_value()).unwrap_or(serde_json::Value::Null)
    }
}

fn parse_node(id: &str, o: &serde_json::Map<String, serde_json::Value>) -> Option<Node> {
    let kind: NodeKind = from_json(json!(o.get("kind")?.as_str()?)).ok()?;
    let label = o
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    
    let mut node = Node::new(NodeId::new(id), kind, label, read_prov(o));
    node.compromise_level = o
        .get("compromise")
        .and_then(|v| v.as_str())
        .and_then(|s| from_json::<CompromiseLevel>(json!(s)).ok())
        .unwrap_or_default();
    
    if let Some(serde_json::Value::Object(idm)) = o.get("identity") {
        for v in idm.values() {
            if let Some(k) = v
                .as_str()
                .and_then(|s| serde_json::from_str::<IdentityKey>(s).ok())
            {
                node.identity_keys.push(k);
            }
        }
    }
    
    if let Some(serde_json::Value::Object(fm)) = o.get("fields") {
        for (k, v) in fm {
            if let Some(val) = v
                .as_str()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            {
                node.fields.insert(k.clone(), val);
            }
        }
    }
    
    if let Some(serde_json::Value::Object(tm)) = o.get("tags") {
        for (k, v) in tm {
            if v.as_bool() == Some(true) {
                node.tags.insert(k.clone());
            }
        }
    }
    
    Some(node)
}

fn parse_edge(id: &str, o: &serde_json::Map<String, serde_json::Value>) -> Option<Edge> {
    let kind: EdgeKind = from_json(json!(o.get("kind")?.as_str()?)).ok()?;
    let source = NodeId::new(o.get("source")?.as_str()?);
    let target = NodeId::new(o.get("target")?.as_str()?);
    
    let mut edge = Edge::new(EdgeId::new(id), kind, source, target, read_prov(o));
    edge.confidence = o
        .get("confidence")
        .and_then(|v| v.as_str())
        .and_then(|s| from_json::<Confidence>(json!(s)).ok())
        .unwrap_or_default();
    
    if let Some(serde_json::Value::Object(fm)) = o.get("fields") {
        for (k, v) in fm {
            if let Some(val) = v
                .as_str()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            {
                edge.fields.insert(k.clone(), val);
            }
        }
    }
    
    if let Some(serde_json::Value::Object(em)) = o.get("evidence") {
        for (k, v) in em {
            if v.as_bool() == Some(true) {
                edge.evidence.push(k.clone());
            }
        }
    }
    
    Some(edge)
}

fn parse_credential(
    id: &str,
    o: &serde_json::Map<String, serde_json::Value>,
) -> Option<Credential> {
    // Canonical key is `credential_type` (matches the web codec); fall back to the
    // legacy `type` key so credentials in pre-unification Rust-only campaigns still parse.
    let ct_str = o
        .get("credential_type")
        .or_else(|| o.get("type"))?
        .as_str()?;
    let credential_type: CredentialType = from_json(json!(ct_str)).ok()?;
    let tested_against = match o.get("tested_against") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| serde_json::from_str::<TestResult>(s).ok())
            .collect(),
        _ => Vec::new(),
    };
    
    Some(Credential {
        id: CredentialId::new(id),
        username: o
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        domain: o.get("domain").and_then(|v| v.as_str()).map(str::to_owned),
        credential_type,
        secret_sealed: o
            .get("secret_sealed")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        belongs_to: o
            .get("belongs_to")
            .and_then(|v| v.as_str())
            .map(NodeId::new),
        obtained_from: o
            .get("obtained_from")
            .and_then(|v| v.as_str())
            .map(NodeId::new),
        validity: o
            .get("validity")
            .and_then(|v| v.as_str())
            .and_then(|s| from_json::<ValidityState>(json!(s)).ok())
            .unwrap_or_default(),
        validity_as_of: o
            .get("validity_as_of")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        source: o
            .get("source")
            .and_then(|v| v.as_str())
            .and_then(|s| from_json::<CredentialSource>(json!(s)).ok())
            .unwrap_or(CredentialSource::Manual),
        tested_against,
        provenance: read_prov(o),
    })
}

#[cfg(test)]
mod tests;
