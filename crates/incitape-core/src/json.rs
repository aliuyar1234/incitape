use crate::error::{AppError, AppResult};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Digest;

pub fn to_canonical_json_bytes<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    let mut json_value = serde_json::to_value(value)
        .map_err(|e| AppError::internal(format!("json serialize error: {e}")))?;
    sort_json_value(&mut json_value);
    serde_json::to_vec(&json_value)
        .map_err(|e| AppError::internal(format!("json encode error: {e}")))
}

pub fn determinism_hash_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn determinism_hash_for_json_value(
    mut value: Value,
    determinism_field: &str,
) -> AppResult<String> {
    let obj = value
        .as_object_mut()
        .ok_or_else(|| AppError::validation("determinism hash value must be an object"))?;
    obj.insert(determinism_field.to_string(), Value::String(String::new()));
    let bytes = to_canonical_json_bytes(&value)?;
    Ok(determinism_hash_hex(&bytes))
}

fn sort_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut new_map = Map::new();
            for key in keys {
                if let Some(mut v) = map.remove(&key) {
                    sort_json_value(&mut v);
                    new_map.insert(key, v);
                }
            }
            *map = new_map;
        }
        Value::Array(items) => {
            for item in items {
                sort_json_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct Example {
        b: i32,
        a: i32,
        map: BTreeMap<String, i32>,
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), 1);
        map.insert("a".to_string(), 2);
        let example = Example { b: 2, a: 1, map };

        let first = to_canonical_json_bytes(&example).unwrap();
        let second = to_canonical_json_bytes(&example).unwrap();
        assert_eq!(first, second);

        let s = String::from_utf8(first).unwrap();
        assert!(s.find("\"a\"").unwrap() < s.find("\"b\"").unwrap());
        assert!(s.find("\"a\"").unwrap() < s.find("\"z\"").unwrap());
    }

    #[test]
    fn determinism_hash_is_stable() {
        let data = b"{\"a\":1}";
        let h1 = determinism_hash_hex(data);
        let h2 = determinism_hash_hex(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn determinism_hash_for_value_uses_placeholder() {
        let mut map = serde_json::Map::new();
        map.insert("a".to_string(), serde_json::Value::from(1));
        map.insert(
            "determinism_hash".to_string(),
            serde_json::Value::String("ignored".to_string()),
        );
        let value = serde_json::Value::Object(map);
        let hash = determinism_hash_for_json_value(value, "determinism_hash").unwrap();
        assert_eq!(hash.len(), 64);
    }
}
