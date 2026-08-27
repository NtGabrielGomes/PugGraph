//! NetExec / CrackMapExec console-output importer.
//!
//! Parses the line-oriented output NetExec (`nxc`) and CrackMapExec print —
//! `PROTO  IP  PORT  HOST  [status] domain\user:secret (Pwn3d!)` — into the
//! campaign graph: hosts become nodes, a `(Pwn3d!)` marks local-admin
//! compromise, and validated credentials become vault records whose
//! `tested_against` list ties each principal to the hosts it opens. Best-effort
//! and total: an unrecognized line is skipped, never fatal, so a whole
//! engagement log (or hostile bytes) is safe to feed.
//!
//! The importer records credential *existence* and where-valid, not the secret:
//! it has no vault key (the browser import path, which does, seals it). The
//! operator fills in the secret in-vault afterward.

use crate::error::ImportError;
use crate::{import_provenance, ImportSummary};
use crdt::{CampaignDoc, CrdtError};
use domain::{
    CompromiseLevel, Credential, CredentialId, CredentialSource, CredentialType, IdentityKey,
    IdentityKeyKind, NodeId, NodeKind, OperatorId, TestResult, Timestamp, ValidityState,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NxcHost {
    pub protocol: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NxcCred {
    pub host_ip: String,
    pub domain: Option<String>,
    pub username: String,
    pub is_hash: bool,
    pub success: bool,
    pub admin: bool,
}

#[derive(Debug, Default)]
pub struct NxcOutput {
    pub hosts: Vec<NxcHost>,
    pub creds: Vec<NxcCred>,
}

/// Parse NetExec/CME console output. Total: any input yields an `NxcOutput`
/// (unrecognized lines are skipped), never a panic. The `Result` exists only for
/// symmetry with the other parsers — this one never returns `Err`.
pub fn parse(text: &str) -> Result<NxcOutput, ImportError> {
    let mut out = NxcOutput::default();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new(); // ip -> index in out.hosts

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 4 {
            continue;
        }
        let protocol = toks[0];
        if protocol.len() > 8 || !protocol.chars().all(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let ip = toks[1];
        if !looks_like_host(ip) {
            continue;
        }
        let hostname = toks.get(3).filter(|t| !t.starts_with('[')).map(|s| s.to_string());

        let idx = *seen.entry(ip.to_string()).or_insert_with(|| {
            out.hosts.push(NxcHost {
                protocol: protocol.to_string(),
                ip: ip.to_string(),
                hostname: hostname.clone(),
                os: None,
            });
            out.hosts.len() - 1
        });
        if out.hosts[idx].hostname.is_none() {
            out.hosts[idx].hostname = hostname;
        }

        if let Some(pos) = line.find("[*]") {
            let rest = line[pos + 3..].trim();
            let os = rest.split('(').next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if out.hosts[idx].os.is_none() {
                out.hosts[idx].os = os;
            }
        } else if let Some((success, pos)) = line
            .find("[+]")
            .map(|p| (true, p))
            .or_else(|| line.find("[-]").map(|p| (false, p)))
        {
            if let Some(cred) = parse_cred(line[pos + 3..].trim(), ip, success) {
                out.creds.push(cred);
            }
        }
    }
    Ok(out)
}

fn looks_like_host(s: &str) -> bool {
    !s.is_empty()
        && (s.contains('.') || s.contains(':'))
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
}

fn parse_cred(rest: &str, host_ip: &str, success: bool) -> Option<NxcCred> {
    let admin = rest.contains("(Pwn3d!)");
    let first = rest.split_whitespace().next()?;
    let (principal, secret) = first.split_once(':')?;
    let (domain, username) = match principal.split_once('\\') {
        Some((d, u)) => (Some(d.to_string()), u.to_string()),
        None => (None, principal.to_string()),
    };
    if username.is_empty() {
        return None;
    }
    Some(NxcCred {
        host_ip: host_ip.to_string(),
        domain,
        username,
        is_hash: looks_like_hash(secret),
        success,
        admin,
    })
}

fn looks_like_hash(secret: &str) -> bool {
    // A bare 32-hex NT hash, or the NT half of an `LM:NT` pair.
    let candidate = secret.rsplit(':').next().unwrap_or(secret);
    candidate.len() == 32 && candidate.chars().all(|c| c.is_ascii_hexdigit())
}

/// Apply parsed NetExec output, reconciling hosts and aggregating each
/// principal's validated hosts into one vault record.
pub fn apply_netexec(
    doc: &CampaignDoc,
    out: &NxcOutput,
    author: &OperatorId,
    now: Timestamp,
) -> Result<ImportSummary, CrdtError> {
    let prov = import_provenance(author, now, "netexec");
    let mut summary = ImportSummary::default();
    let mut host_ids: BTreeMap<String, NodeId> = BTreeMap::new();

    for h in &out.hosts {
        let mut ikeys = vec![IdentityKey::primary(IdentityKeyKind::IpAddress, h.ip.clone())];
        if let Some(hn) = &h.hostname {
            ikeys.push(IdentityKey::new(IdentityKeyKind::Hostname, hn.to_lowercase()));
        }
        let label = h.hostname.clone().unwrap_or_else(|| h.ip.clone());
        let id = doc.resolve_or_create(&ikeys, guess_kind(h.os.as_deref()), &label, &prov)?;
        if let Some(os) = &h.os {
            doc.set_node_field(&id, "os_version", &serde_json::json!(os))?;
        }
        host_ids.insert(h.ip.clone(), id);
        summary.hosts += 1;
    }

    // A host where any principal pwned us is locally admin-compromised.
    for c in &out.creds {
        if c.admin && c.success {
            if let Some(id) = host_ids.get(&c.host_ip) {
                doc.set_compromise(id, CompromiseLevel::Admin)?;
            }
        }
    }

    // Aggregate by principal, listing every host each credential opened.
    let mut creds: BTreeMap<(Option<String>, String), (bool, CredentialType, Vec<TestResult>)> =
        BTreeMap::new();
    for c in &out.creds {
        let Some(host_id) = host_ids.get(&c.host_ip).cloned() else { continue };
        let entry = creds.entry((c.domain.clone(), c.username.clone())).or_insert_with(|| {
            let t = if c.is_hash { CredentialType::PasswordNtlm } else { CredentialType::PasswordPlaintext };
            (false, t, Vec::new())
        });
        entry.0 |= c.success;
        entry.2.push(TestResult { host: host_id, succeeded: c.success, at: now, note: None });
    }
    for ((domain, username), (any_valid, ctype, tested)) in creds {
        let id = CredentialId::new(format!(
            "nxc:{}\\{}",
            domain.clone().unwrap_or_default().to_lowercase(),
            username.to_lowercase()
        ));
        doc.add_credential(&Credential {
            id,
            username,
            domain,
            credential_type: ctype,
            secret_sealed: None,
            belongs_to: None,
            obtained_from: None,
            validity: if any_valid { ValidityState::Valid } else { ValidityState::Invalid },
            validity_as_of: now,
            source: CredentialSource::Spray,
            tested_against: tested,
            provenance: prov.clone(),
        })?;
        summary.credentials += 1;
    }

    Ok(summary)
}

fn guess_kind(os: Option<&str>) -> NodeKind {
    match os.map(|s| s.to_ascii_lowercase()) {
        Some(s) if s.contains("windows") => NodeKind::HostWindows,
        Some(s) if s.contains("linux") => NodeKind::HostLinux,
        Some(s) if s.contains("mac") || s.contains("darwin") => NodeKind::HostMacos,
        _ => NodeKind::HostWindows,
    }
}
