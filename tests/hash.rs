use hash_attestation::canonical_hash;

#[test]
fn identical_inputs_hash_identically() {
    let a = serde_json::json!({"foo": 1, "bar": "x"});
    let b = serde_json::json!({"bar": "x", "foo": 1});
    assert_eq!(canonical_hash(&a).unwrap(), canonical_hash(&b).unwrap());
}

#[test]
fn different_inputs_hash_differently() {
    let a = serde_json::json!({"foo": 1});
    let b = serde_json::json!({"foo": 2});
    assert_ne!(canonical_hash(&a).unwrap(), canonical_hash(&b).unwrap());
}

#[test]
fn hash_string_starts_with_sha256_prefix() {
    let v = serde_json::json!({"x": 1});
    let h = canonical_hash(&v).unwrap();
    assert!(h.starts_with("sha256:"));
    // sha256 is 32 bytes => 64 hex chars
    assert_eq!(h.len(), "sha256:".len() + 64);
}

#[test]
fn hash_is_stable_across_runs() {
    // Golden hash for `{"a":1,"b":[true,null]}` after canonicalisation.
    let v = serde_json::json!({"b": [true, null], "a": 1});
    let h = canonical_hash(&v).unwrap();
    assert_eq!(
        h,
        "sha256:1cc69c7fa23616ca2ec3ee70d24390a6225c8832db8a4c814c7e0e7f942f8668"
    );
}

#[test]
fn whitespace_in_string_values_preserved() {
    let a = serde_json::json!({"name": "Acme  Inc."});
    let b = serde_json::json!({"name": "Acme Inc."});
    assert_ne!(canonical_hash(&a).unwrap(), canonical_hash(&b).unwrap());
}

#[test]
fn numeric_exponent_hash_locks_current_rust_format() {
    let v = serde_json::json!({"x": 1e-7});
    assert_eq!(serde_json::to_string(&v).unwrap(), r#"{"x":1e-7}"#);
    assert_eq!(
        canonical_hash(&v).unwrap(),
        "sha256:43c8e92bd5552bd45030718eb9366d6d6500623793c248666d77dca01ba337c0"
    );
}

#[test]
fn unicode_hash_locks_current_rust_format() {
    let v = serde_json::json!({"name": "Café"});
    assert_eq!(serde_json::to_string(&v).unwrap(), r#"{"name":"Café"}"#);
    assert_eq!(
        canonical_hash(&v).unwrap(),
        "sha256:659906f125d844f7081786e4a1cba739414e49a9b9061d80ce09c691b5f56602"
    );
}
