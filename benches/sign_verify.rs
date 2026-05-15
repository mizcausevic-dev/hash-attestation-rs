//! Throughput micro-bench for sign + verify. Run with `cargo bench`.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use hash_attestation::Attestor;
use rand_core::OsRng;

fn sample_body() -> serde_json::Value {
    serde_json::json!({
        "aeo_version": "0.1",
        "entity": {
            "id": "https://acmetutor.example/#org",
            "kind": "Organization",
            "name": "AcmeTutor Inc.",
        },
        "authority": {"primary_sources": ["https://acmetutor.example/"]},
        "claims": [
            {"id": "tag", "predicate": "industry", "value": "AI tutoring", "confidence": "high"},
            {"id": "hq", "predicate": "headquartered_in", "value": "Boston, MA", "confidence": "high"},
        ],
    })
}

fn bench_sign(c: &mut Criterion) {
    let key = SigningKey::generate(&mut OsRng);
    let attestor = Attestor::new(key, "https://x/".to_string());
    let body = sample_body();
    c.bench_function("sign_attestation", |b| {
        b.iter(|| {
            let _ = attestor.sign(&body).unwrap();
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let key = SigningKey::generate(&mut OsRng);
    let attestor = Attestor::new(key.clone(), "https://x/".to_string());
    let body = sample_body();
    let signed = attestor.sign(&body).unwrap();
    let verifying_key = key.verifying_key();
    c.bench_function("verify_attestation", |b| {
        b.iter(|| {
            signed.verify(&verifying_key, &body).unwrap();
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30).measurement_time(Duration::from_secs(3));
    targets = bench_sign, bench_verify
}
criterion_main!(benches);
