//! Canonical hashes for the legacy v0.1 format and RFC 8785 profile.

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

use crate::error::AttestationError;

/// Compute `sha256:<hex>` over the legacy v0.1 JSON representation (sorted
/// keys, no whitespace, UTF-8). Other languages may serialize Unicode and
/// floating-point values differently. Use [`canonical_hash_jcs`] for new
/// cross-language attestations.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String, AttestationError> {
    let parsed: serde_json::Value = serde_json::to_value(value)?;
    let canonical = canonicalise(&parsed);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest.as_slice())))
}

/// Compute `sha256:<hex>` over RFC 8785 JCS UTF-8 bytes. This is the
/// `jcs-rfc8785-v1` profile used by new attestations. For raw JSON, use
/// [`parse_jcs_json_strict`] before parsing through a lossy JSON decoder.
/// Already-parsed values cannot reveal duplicate keys in their original text.
pub fn canonical_hash_jcs<T: serde::Serialize>(value: &T) -> Result<String, AttestationError> {
    crate::validate::check_finite(value)?;
    // The finite-number pass rejects NaN/infinity, which serde_json's ordinary
    // serializer would otherwise turn into `null`. The second catches unsafe
    // integers and duplicate fields, including custom Serialize maps. Compare
    // both views to reject serializers that produce different JSON each pass.
    let canonical = serde_json_canonicalizer::to_vec(value)?;
    let raw = serde_json::to_vec(value)?;
    let parsed = parse_jcs_json_strict_bytes(&raw)?;
    if serde_json_canonicalizer::to_vec(&parsed)? != canonical {
        return Err(AttestationError::InvalidJcsInput(
            "serialization changed between JCS and JSON passes".to_string(),
        ));
    }
    let digest = Sha256::digest(&canonical);
    Ok(format!("sha256:{}", hex::encode(digest.as_slice())))
}

/// Parse raw JSON for the JCS profile, rejecting duplicate object keys,
/// unpaired Unicode surrogates, and integer values outside the interoperable
/// IEEE-754 safe integer range. Normal JSON whitespace and key order are
/// accepted. A pre-parsed JSON value cannot recover discarded duplicate keys.
pub fn parse_jcs_json_strict(raw: &str) -> Result<serde_json::Value, AttestationError> {
    parse_jcs_json_strict_bytes(raw.as_bytes())
}

fn parse_jcs_json_strict_bytes(raw: &[u8]) -> Result<serde_json::Value, AttestationError> {
    reject_unsafe_integer_literals(raw)?;
    Ok(serde_json::from_slice::<StrictJsonValue>(raw)?.0)
}

fn reject_unsafe_integer_literals(raw: &[u8]) -> Result<(), AttestationError> {
    const SAFE: i128 = 9_007_199_254_740_991;
    let mut i = 0;
    let mut quoted = false;
    while i < raw.len() {
        match raw[i] {
            b'\\' if quoted => i += 2,
            b'"' => {
                quoted = !quoted;
                i += 1;
            }
            b'-' | b'0'..=b'9' if !quoted => {
                let start = i;
                i += 1;
                while i < raw.len()
                    && matches!(raw[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    i += 1;
                }
                let number = &raw[start..i];
                if !number.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                    let integer = std::str::from_utf8(number)
                        .ok()
                        .and_then(|s| s.parse::<i128>().ok());
                    if integer.is_none_or(|n| !(-SAFE..=SAFE).contains(&n)) {
                        return Err(AttestationError::InvalidJcsInput(
                            "integer exceeds IEEE-754 safe range".to_string(),
                        ));
                    }
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("I-JSON without duplicate keys or unsafe integers")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        const SAFE: i64 = 9_007_199_254_740_991;
        if !(-SAFE..=SAFE).contains(&value) {
            return Err(E::custom("integer exceeds IEEE-754 safe range"));
        }
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        const SAFE: u64 = 9_007_199_254_740_991;
        if value > SAFE {
            return Err(E::custom("integer exceeds IEEE-754 safe range"));
        }
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        if !value.is_finite() {
            return Err(E::custom("non-finite number"));
        }
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(value.into()))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(values.into()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(StrictJsonValue(values.into()))
    }
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
