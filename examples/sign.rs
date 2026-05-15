//! `cargo run --example sign`
//!
//! Generates a key pair, signs a sample AEO doc, prints the attestation.

use ed25519_dalek::SigningKey;
use hash_attestation::{Attestor, Verifier};
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({
        "aeo_version": "0.1",
        "entity": {
            "id": "https://acmetutor.example/#org",
            "kind": "Organization",
            "name": "AcmeTutor Inc.",
            "canonical_url": "https://acmetutor.example/",
        },
        "authority": {"primary_sources": ["https://acmetutor.example/"]},
        "claims": [],
    });

    // Vendor: sign.
    let key = SigningKey::generate(&mut OsRng);
    let attestor = Attestor::new(
        key.clone(),
        "https://acmetutor.example/keys/aeo".to_string(),
    );
    let attestation = attestor.sign(&body)?;
    println!("attestation:");
    println!("{}", serde_json::to_string_pretty(&attestation)?);

    // Consumer: verify.
    let mut verifier = Verifier::new();
    verifier.trust(attestor.key_url(), attestor.verifying_key());
    verifier.verify(&attestation, &body)?;
    println!("\nverify: ok");

    Ok(())
}
