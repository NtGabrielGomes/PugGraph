//! Nmap XML parser.
//!
//! Pure, total parsing: hostile or malformed input yields an `Err`, never a
//! panic or unbounded allocation (Rust's memory safety plus roxmltree's
//! read-only DOM). The parser is deliberately separated from graph application
//! so it can be fuzzed in isolation.

use crate::error::ImportError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPort {
    pub portid: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedHost {
    pub ipv4: Option<String>,
    pub mac: Option<String>,
    pub hostnames: Vec<String>,
    pub os: Option<String>,
    pub ports: Vec<ParsedPort>,
}

/// Parse an Nmap XML document into a list of hosts.
pub fn parse(xml: &str) -> Result<Vec<ParsedHost>, ImportError> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| ImportError::Parse(e.to_string()))?;
    let mut hosts = Vec::new();

    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let mut ph = ParsedHost::default();

        for addr in host.children().filter(|n| n.has_tag_name("address")) {
            match addr.attribute("addrtype") {
                Some("ipv4") => ph.ipv4 = addr.attribute("addr").map(str::to_owned),
                Some("mac") => ph.mac = addr.attribute("addr").map(str::to_owned),
                _ => {}
            }
        }

        for hn in host.descendants().filter(|n| n.has_tag_name("hostname")) {
            if let Some(name) = hn.attribute("name") {
                ph.hostnames.push(name.to_owned());
            }
        }

        if let Some(osmatch) = host.descendants().find(|n| n.has_tag_name("osmatch")) {
            ph.os = osmatch.attribute("name").map(str::to_owned);
        }

        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            let Some(portid) = port.attribute("portid").and_then(|s| s.parse::<u16>().ok()) else {
                continue;
            };
            let protocol = port.attribute("protocol").unwrap_or("tcp").to_owned();
            let state = port
                .children()
                .find(|n| n.has_tag_name("state"))
                .and_then(|s| s.attribute("state"))
                .unwrap_or("unknown")
                .to_owned();
            let svc = port.children().find(|n| n.has_tag_name("service"));
            let (service, product, version) = match svc {
                Some(s) => (
                    s.attribute("name").map(str::to_owned),
                    s.attribute("product").map(str::to_owned),
                    s.attribute("version").map(str::to_owned),
                ),
                None => (None, None, None),
            };
            ph.ports.push(ParsedPort { portid, protocol, state, service, product, version });
        }

        hosts.push(ph);
    }

    Ok(hosts)
}
