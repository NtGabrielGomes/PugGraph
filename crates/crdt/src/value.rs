use crate::error::CrdtError;
use loro::{Container, LoroList, LoroMap, LoroValue, ValueOrContainer};
use serde::{de::DeserializeOwned, Serialize};

pub fn get_str(m: &LoroMap, key: &str) -> Option<String> {
    match m.get(key) {
        Some(ValueOrContainer::Value(LoroValue::String(s))) => Some(s.to_string()),
        _ => None,
    }
}

pub fn child_map(parent: &LoroMap, key: &str) -> Result<LoroMap, CrdtError> {
    match parent.get(key) {
        Some(ValueOrContainer::Container(Container::Map(m))) => Ok(m),
        _ => Ok(parent.insert_container(key, LoroMap::new())?),
    }
}

pub fn child_list(parent: &LoroMap, key: &str) -> Result<LoroList, CrdtError> {
    match parent.get(key) {
        Some(ValueOrContainer::Container(Container::List(l))) => Ok(l),
        _ => Ok(parent.insert_container(key, LoroList::new())?),
    }
}

pub fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub fn from_json<T: DeserializeOwned>(v: serde_json::Value) -> Result<T, CrdtError> {
    serde_json::from_value(v).map_err(Into::into)
}

pub fn deep_object(m: &LoroMap) -> Result<serde_json::Map<String, serde_json::Value>, CrdtError> {
    match serde_json::to_value(m.get_deep_value())? {
        serde_json::Value::Object(o) => Ok(o),
        _ => Ok(serde_json::Map::new()),
    }
}

pub fn deep_array(l: &LoroList) -> Result<Vec<serde_json::Value>, CrdtError> {
    match serde_json::to_value(l.get_deep_value())? {
        serde_json::Value::Array(a) => Ok(a),
        _ => Ok(Vec::new()),
    }
}
