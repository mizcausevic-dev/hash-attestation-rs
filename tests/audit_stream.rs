//! Integration tests for the optional `audit-stream` feature.

#![cfg(feature = "audit-stream")]

use ed25519_dalek::SigningKey;
use hash_attestation::{Attestation, Attestor, Verifier};
use rand_core::OsRng;
use serde_json::{json, Value};
use std::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `AUDIT_STREAM_URL` is process-global; serialise tests that mutate it.
static ENV_GUARD: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn lock() -> Self {
        let lock = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::remove_var("AUDIT_STREAM_URL");
        std::env::remove_var("AUDIT_STREAM_TIMEOUT_S");
        EnvGuard { _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("AUDIT_STREAM_URL");
        std::env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }
}

const KEY_URL: &str = "https://acme.example/keys/aeo";

fn sample_body() -> serde_json::Value {
    json!({
        "aeo_version": "0.1",
        "entity": { "id": "https://acme.example/#org", "name": "Acme" }
    })
}

fn build_attestor() -> (Attestor, ed25519_dalek::VerifyingKey) {
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    (Attestor::new(key, KEY_URL.to_string()), vk)
}

#[tokio::test]
async fn sign_with_audit_emits_attestation_signed() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    std::env::set_var("AUDIT_STREAM_URL", server.uri());

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let (attestor, _) = build_attestor();
    let client = reqwest::Client::new();
    let signed = attestor
        .sign_with_audit(&client, &sample_body())
        .await
        .expect("sign");
    assert_eq!(signed.algorithm, "ed25519");
    assert_eq!(signed.key_url, KEY_URL);

    let recvd = server.received_requests().await.unwrap();
    assert_eq!(recvd.len(), 1);
    let body: Value = serde_json::from_slice(&recvd[0].body).unwrap();
    assert_eq!(body["kind"], "attestation_signed");
    assert_eq!(body["source"], "hash-attestation");
    assert_eq!(body["payload"]["key_url"], KEY_URL);
    assert!(body["payload"]["signed_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[tokio::test]
async fn verify_with_audit_emits_attestation_verified_on_success() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    std::env::set_var("AUDIT_STREAM_URL", server.uri());

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(201))
        // Expect 2: one for sign, one for verify.
        .expect(2)
        .mount(&server)
        .await;

    let (attestor, vk) = build_attestor();
    let client = reqwest::Client::new();
    let signed = attestor
        .sign_with_audit(&client, &sample_body())
        .await
        .expect("sign");

    let mut verifier = Verifier::new();
    verifier.trust(KEY_URL, vk);
    verifier
        .verify_with_audit(&client, &signed, &sample_body())
        .await
        .expect("verify");

    let recvd = server.received_requests().await.unwrap();
    assert_eq!(recvd.len(), 2);
    let last: Value = serde_json::from_slice(&recvd[1].body).unwrap();
    assert_eq!(last["kind"], "attestation_verified");
    assert_eq!(last["source"], "hash-attestation");
    assert_eq!(last["payload"]["trusted_keys"], 1);
}

#[tokio::test]
async fn verify_with_audit_emits_attestation_failed_on_tamper() {
    let _guard = EnvGuard::lock();
    let server = MockServer::start().await;
    std::env::set_var("AUDIT_STREAM_URL", server.uri());

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let (attestor, vk) = build_attestor();
    let signed = attestor.sign(&sample_body()).expect("sign");
    let mut verifier = Verifier::new();
    verifier.trust(KEY_URL, vk);

    // Tamper the body. verify should fail and emit attestation_failed.
    let tampered = json!({
        "aeo_version": "0.1",
        "entity": { "id": "https://acme.example/#org", "name": "AcmeTampered" }
    });
    let client = reqwest::Client::new();
    let err = verifier
        .verify_with_audit(&client, &signed, &tampered)
        .await
        .expect_err("verify must fail on tampered body");
    // Just confirm it errored — exact variant doesn't matter for this test.
    let msg = err.to_string();
    assert!(!msg.is_empty());

    let recvd = server.received_requests().await.unwrap();
    assert_eq!(recvd.len(), 1);
    let body: Value = serde_json::from_slice(&recvd[0].body).unwrap();
    assert_eq!(body["kind"], "attestation_failed");
    assert_eq!(body["source"], "hash-attestation");
    assert!(body["payload"]["reason"].as_str().is_some());
}

#[tokio::test]
async fn emit_silent_when_env_var_unset() {
    let _guard = EnvGuard::lock();
    // No AUDIT_STREAM_URL set.
    let server = MockServer::start().await;
    let (attestor, _) = build_attestor();
    let client = reqwest::Client::new();
    let _ = attestor
        .sign_with_audit(&client, &sample_body())
        .await
        .expect("sign");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn audit_outage_does_not_break_sign() {
    let _guard = EnvGuard::lock();
    // Port nothing listens on. sign must still succeed.
    std::env::set_var("AUDIT_STREAM_URL", "http://127.0.0.1:1");

    let (attestor, _) = build_attestor();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let signed: Attestation = attestor
        .sign_with_audit(&client, &sample_body())
        .await
        .expect("sign must succeed despite audit outage");
    assert_eq!(signed.key_url, KEY_URL);
}
