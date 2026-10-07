use ed25519_dalek::{Signer, SigningKey};
use hash_attestation::{canonical_hash, canonical_hash_jcs, Attestation, AttestationError};
use serde_json::Value;

fn check_v2_vector(source: &str) {
    let vector: Value = serde_json::from_str(source).unwrap();
    let body = &vector["body"];
    let canonical = serde_json_canonicalizer::to_string(body).unwrap();
    assert_eq!(canonical, vector["canonical_body"].as_str().unwrap());
    assert_eq!(
        canonical_hash_jcs(body).unwrap(),
        vector["signed_hash"].as_str().unwrap()
    );

    let signed: Attestation = serde_json::from_value(vector["attestation"].clone()).unwrap();
    assert_eq!(signed.hash_profile.as_deref(), vector["profile"].as_str());
    let key = SigningKey::from_bytes(&[7u8; 32]);
    signed.verify(&key.verifying_key(), body).unwrap();

    // Independently generated Python rfc8785 + cryptography signature checks
    // the exact JCS payload and domain separator used on the wire.
    let signature = key.sign(&signed.signing_input_v2().unwrap());
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );
    assert_eq!(encoded, signed.signature);
}

#[test]
fn unicode_numeric_and_utf16_order_vector_matches_python() {
    check_v2_vector(include_str!("vectors/jcs-rfc8785-v1.json"));
}

#[test]
fn decision_card_vector_matches_python() {
    check_v2_vector(include_str!("vectors/decision-card-v2.json"));
}

#[test]
fn legacy_v01_wire_record_still_verifies() {
    let vector: Value = serde_json::from_str(include_str!("vectors/legacy-v0.1.json")).unwrap();
    let body = &vector["body"];
    assert_eq!(
        canonical_hash(body).unwrap(),
        vector["signed_hash"].as_str().unwrap()
    );
    let signed: Attestation = serde_json::from_value(vector["attestation"].clone()).unwrap();
    assert!(signed.hash_profile.is_none());
    let key = SigningKey::from_bytes(&[7u8; 32]);
    signed.verify(&key.verifying_key(), body).unwrap();
    let mut changed_time = signed.clone();
    changed_time.signed_at = "2000-01-01T00:00:00Z".to_string();
    changed_time.verify(&key.verifying_key(), body).unwrap();
    let mut changed_body = body.clone();
    changed_body["name"] = "Different".into();
    assert!(matches!(
        signed.verify(&key.verifying_key(), &changed_body),
        Err(AttestationError::HashMismatch { .. })
    ));
}
