use ed25519_dalek::SigningKey;
use hash_attestation::{canonical_hash_jcs, parse_jcs_json_strict, Attestor, Verifier};
use serde::ser::SerializeMap;
use serde::Serialize;

struct DuplicateFields;

impl Serialize for DuplicateFields {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("x", &1)?;
        map.serialize_entry("x", &2)?;
        map.end()
    }
}

#[test]
fn strict_parse_rejects_duplicate_keys_and_unsafe_integers() {
    for raw in [
        r#"{"x":1,"x":2}"#,
        r#"{"nested":{"x":1,"x":2}}"#,
        r#"{"x":9007199254740992}"#,
        r#"{"x":18446744073709551616}"#,
        r#"{"x":-9007199254740992}"#,
        r#"{"x":"\uD800"}"#,
    ] {
        assert!(parse_jcs_json_strict(raw).is_err(), "accepted: {raw}");
    }
    assert!(parse_jcs_json_strict(r#"{"x":9007199254740991}"#).is_ok());
    assert!(parse_jcs_json_strict(r#"{"x":1e20}"#).is_ok());
    assert!(parse_jcs_json_strict(r#"{"x":1e-7}"#).is_ok());
}

#[test]
fn jcs_hash_rejects_nonfinite_and_duplicate_custom_serializers() {
    assert!(canonical_hash_jcs(&serde_json::json!({"x": 9_007_199_254_740_992u64})).is_err());
    assert!(canonical_hash_jcs(&serde_json::json!({"x": 9_007_199_254_740_991u64})).is_ok());
    assert!(canonical_hash_jcs(&serde_json::json!({"x": 1e20})).is_ok());
    assert!(canonical_hash_jcs(&serde_json::json!({"x": 1e-7})).is_ok());
    assert!(canonical_hash_jcs(&DuplicateFields).is_err());
    assert!(canonical_hash_jcs(&[f64::NAN]).is_err());
    assert!(canonical_hash_jcs(&[f64::INFINITY]).is_err());
}

#[test]
fn raw_sign_and_verify_reject_lossy_input() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let key_url = "https://vendor.example/keys/aeo";
    let attestor = Attestor::new(key.clone(), key_url.to_string());
    let raw = r#"{"name":"Café","x":1e-7}"#;
    let signed = attestor.sign_raw_json(raw).unwrap();
    let mut verifier = Verifier::new();
    verifier.trust(key_url, key.verifying_key());
    verifier
        .verify_raw_json_for_key_url(key_url, &signed, raw)
        .unwrap();
    signed.verify_raw_json(&key.verifying_key(), raw).unwrap();
    assert!(attestor.sign_raw_json(r#"{"x":1,"x":2}"#).is_err());
    assert!(verifier
        .verify_raw_json_for_key_url(key_url, &signed, r#"{"name":"Café","x":1e-7,"x":1e-7}"#)
        .is_err());
}

#[test]
fn unicode_is_not_normalized() {
    let composed = parse_jcs_json_strict(r#"{"name":"Café"}"#).unwrap();
    let decomposed = parse_jcs_json_strict(r#"{"name":"Cafe\u0301"}"#).unwrap();
    assert_ne!(
        canonical_hash_jcs(&composed).unwrap(),
        canonical_hash_jcs(&decomposed).unwrap()
    );
}
