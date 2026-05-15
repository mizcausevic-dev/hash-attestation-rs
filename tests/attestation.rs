use ed25519_dalek::SigningKey;
use hash_attestation::{Attestation, AttestationError, Attestor, Verifier};
use rand_core::OsRng;

fn body() -> serde_json::Value {
    serde_json::json!({
        "aeo_version": "0.1",
        "entity": {"id": "https://acme.example/#org", "name": "Acme"},
    })
}

fn keypair_and_attestor(key_url: &str) -> (SigningKey, Attestor) {
    let key = SigningKey::generate(&mut OsRng);
    let attestor = Attestor::new(key.clone(), key_url.to_string());
    (key, attestor)
}

#[test]
fn sign_and_verify_round_trip() {
    let (key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    assert!(signed.verify(&key.verifying_key(), &body()).is_ok());
}

#[test]
fn tampered_body_fails_verify_with_hash_mismatch() {
    let (key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    let mut tampered = body();
    tampered["entity"]["name"] = serde_json::Value::from("AcmeCorp");
    let err = signed.verify(&key.verifying_key(), &tampered).unwrap_err();
    assert!(matches!(err, AttestationError::HashMismatch { .. }));
}

#[test]
fn wrong_key_fails_verify() {
    let (_real_key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    let other = SigningKey::generate(&mut OsRng);
    let err = signed.verify(&other.verifying_key(), &body()).unwrap_err();
    assert!(matches!(err, AttestationError::BadSignature));
}

#[test]
fn unsupported_algorithm_rejected() {
    let mut signed = Attestation {
        algorithm: "rsa-sha256".to_string(),
        signed_hash: "sha256:00".to_string(),
        signature: "AAAA".to_string(),
        key_url: "https://x/".to_string(),
        signed_at: "2026-05-15T00:00:00Z".to_string(),
    };
    // Fake key, doesn't matter — we should bail on the algorithm check first.
    let key = SigningKey::generate(&mut OsRng).verifying_key();
    let err = signed.verify(&key, &body()).unwrap_err();
    assert!(matches!(err, AttestationError::UnsupportedAlgorithm(_)));

    signed.algorithm = "ed25519".to_string();
    signed.signature = "not-base64".to_string();
    let err = signed.verify(&key, &body()).unwrap_err();
    // Now it should make it past the algorithm check; the next failure is
    // a base64-decode or hash-mismatch.
    assert!(
        matches!(
            err,
            AttestationError::InvalidBase64(_) | AttestationError::HashMismatch { .. }
        ),
        "got: {err:?}"
    );
}

#[test]
fn verifier_with_trusted_set() {
    let (key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();

    let mut verifier = Verifier::new();
    verifier.trust("https://acme.example/keys/aeo", key.verifying_key());
    assert!(verifier.verify(&signed, &body()).is_ok());
    assert_eq!(verifier.len(), 1);
    assert!(!verifier.is_empty());
}

#[test]
fn verifier_rejects_untrusted_key_url() {
    let (_key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();

    let verifier = Verifier::new();
    let err = verifier.verify(&signed, &body()).unwrap_err();
    assert!(matches!(err, AttestationError::UntrustedKey(_)));
}

#[test]
fn attestation_round_trips_through_json() {
    let (_key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    let s = serde_json::to_string(&signed).unwrap();
    let parsed: Attestation = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed, signed);
}

#[test]
fn signed_at_is_z_suffixed() {
    let (_key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    assert!(signed.signed_at.ends_with('Z'), "got: {}", signed.signed_at);
}
