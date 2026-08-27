//! The cross-language schema contract. The Rust domain is the single source of
//! truth for the node / edge / identity-key vocabularies; this module serializes
//! them to a committed `schema.json` fixture that the web client validates its
//! mirror against (see `web/test/schema.test.ts`), so the two can never drift
//! without a test going red. This complements `constraints.rs`'s `edge_matrix.json`
//! (which fixes the per-edge endpoint *rules*); together they pin the whole schema.

use crate::constraints::{ALL_EDGE_KINDS, ALL_NODE_KINDS};
use crate::identity::ALL_IDENTITY_KEY_KINDS;
use serde::Serialize;

/// snake_case serde representation of an enum value (matches the wire form the
/// web's string-union types use).
fn token<T: Serialize>(t: &T) -> String {
    serde_json::to_value(t)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

/// The schema as JSON: the ordered vocabularies the web mirror must reproduce.
pub fn schema() -> serde_json::Value {
    serde_json::json!({
        "node_kinds": ALL_NODE_KINDS.iter().map(token).collect::<Vec<_>>(),
        "edge_kinds": ALL_EDGE_KINDS.iter().map(token).collect::<Vec<_>>(),
        "identity_keys": ALL_IDENTITY_KEY_KINDS.iter().map(token).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_fixture() {
        let built = schema();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/schema.json");
        if std::env::var("UPDATE_SCHEMA").is_ok() {
            std::fs::write(path, serde_json::to_string_pretty(&built).unwrap()).unwrap();
            return;
        }
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture exists")).unwrap();
        assert_eq!(
            built, committed,
            "schema vocabulary changed. regenerate with UPDATE_SCHEMA=1 and mirror in web (types.ts/catalog.ts)"
        );
    }
}
