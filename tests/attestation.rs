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
        hash_profile: None,
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
fn vendor_specific_verification_rejects_another_trusted_vendor() {
    let (key_a, _vendor_a) = keypair_and_attestor("https://vendor-a.example/keys/aeo");
    let (key_b, vendor_b) = keypair_and_attestor("https://vendor-b.example/keys/aeo");
    let signed_by_b = vendor_b.sign(&body()).unwrap();

    let mut verifier = Verifier::new();
    verifier.trust("https://vendor-a.example/keys/aeo", key_a.verifying_key());
    verifier.trust("https://vendor-b.example/keys/aeo", key_b.verifying_key());

    // Generic verification is valid for B's key, but a request for A's
    // document must bind to A's independently known key URL.
    assert!(verifier.verify(&signed_by_b, &body()).is_ok());
    let err = verifier
        .verify_for_key_url("https://vendor-a.example/keys/aeo", &signed_by_b, &body())
        .unwrap_err();
    assert!(matches!(err, AttestationError::UntrustedKey(_)));
    assert!(verifier
        .verify_for_key_url("https://vendor-b.example/keys/aeo", &signed_by_b, &body())
        .is_ok());

    let mut switched_selector = signed_by_b.clone();
    switched_selector.key_url = "https://vendor-a.example/keys/aeo".to_string();
    let err = verifier
        .verify_for_key_url(
            "https://vendor-a.example/keys/aeo",
            &switched_selector,
            &body(),
        )
        .unwrap_err();
    assert!(matches!(err, AttestationError::BadSignature));
}

#[test]
fn advisory_timestamp_is_not_authenticated() {
    let (key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let mut signed = attestor.sign_legacy(&body()).unwrap();
    signed.signed_at = "1900-01-01T00:00:00Z".to_string();
    assert!(signed.verify(&key.verifying_key(), &body()).is_ok());
}

#[test]
fn v2_metadata_is_authenticated() {
    let (key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    assert_eq!(signed.hash_profile.as_deref(), Some("jcs-rfc8785-v1"));

    let mut changed_time = signed.clone();
    changed_time.signed_at = "1900-01-01T00:00:00Z".to_string();
    assert!(matches!(
        changed_time.verify(&key.verifying_key(), &body()),
        Err(AttestationError::BadSignature)
    ));

    let mut changed_url = signed.clone();
    changed_url.key_url = "https://other.example/keys/aeo".to_string();
    assert!(matches!(
        changed_url.verify(&key.verifying_key(), &body()),
        Err(AttestationError::BadSignature)
    ));

    let mut changed_algorithm = signed.clone();
    changed_algorithm.algorithm = "rsa-sha256".to_string();
    assert!(matches!(
        changed_algorithm.verify(&key.verifying_key(), &body()),
        Err(AttestationError::UnsupportedAlgorithm(_))
    ));

    let mut removed_profile = signed.clone();
    removed_profile.hash_profile = None;
    assert!(matches!(
        removed_profile.verify(&key.verifying_key(), &body()),
        Err(AttestationError::BadSignature)
    ));

    let mut unknown_profile = signed;
    unknown_profile.hash_profile = Some("unrecognized".to_string());
    assert!(matches!(
        unknown_profile.verify(&key.verifying_key(), &body()),
        Err(AttestationError::UnsupportedHashProfile(_))
    ));
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

#[test]
fn wire_record_rejects_ambiguous_or_unsigned_extra_fields() {
    let (_key, attestor) = keypair_and_attestor("https://acme.example/keys/aeo");
    let signed = attestor.sign(&body()).unwrap();
    let mut wire = serde_json::to_value(&signed).unwrap();
    wire["hash_profile"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Attestation>(wire).is_err());

    let mut wire = serde_json::to_value(&signed).unwrap();
    wire["vendor_identity"] = "unspecified".into();
    assert!(serde_json::from_value::<Attestation>(wire).is_err());
}
