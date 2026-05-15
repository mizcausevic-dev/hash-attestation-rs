//! Canonical-hash function. Identical convention to `procurement-decision-api`
//! and `aeo-validator-service`, so the same input bytes produce the same hash
//! across the portfolio.

use sha2::{Digest, Sha256};

use crate::error::AttestationError;

/// Compute `sha256:<hex>` over canonical JSON (sorted keys, no whitespace,
/// UTF-8). Accepts anything `serde::Serialize`.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String, AttestationError> {
    let parsed: serde_json::Value = serde_json::to_value(value)?;
    let canonical = canonicalise(&parsed);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest.as_slice())))
}

/// Canonical form of a `serde_json::Value`: object keys sorted; no whitespace.
/// `serde_json::to_string` doesn't sort keys, so we walk the tree ourselves.
fn canonicalise(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write(&mut out, value);
    out
}

fn write(out: &mut String, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap()),
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, item);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap());
                out.push(':');
                write(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

// Avoid a `hex` runtime dep by inlining a tiny hex encoder.
mod hex {
    pub(super) fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}
