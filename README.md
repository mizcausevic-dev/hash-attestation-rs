# hash-attestation

[![CI](https://github.com/mizcausevic-dev/hash-attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/hash-attestation-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Sign Kinetic Gain Protocol Suite JSON documents with Ed25519 and verify their content against a **previously trusted public key**. This crate provides local signing and verification. It does not fetch keys or establish who owns them.

```rust
use hash_attestation::{Attestation, Attestor, Verifier};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() -> Result<(), hash_attestation::AttestationError> {
    let key = SigningKey::generate(&mut OsRng);
    let key_url = "https://acme.example/keys/aeo";
    let attestor = Attestor::new(key, key_url.to_string());
    let body = serde_json::json!({"aeo_version": "0.1", "entity": {"name": "Acme"}});
    let signed: Attestation = attestor.sign(&body)?;

    // In production, establish this key and its vendor binding through an
    // independently authenticated source. Do not trust a key merely because
    // the attestation supplies a URL for it.
    let mut verifier = Verifier::new();
    verifier.trust(key_url, attestor.verifying_key());
    verifier.verify_for_key_url(key_url, &signed, &body)?;
    Ok(())
}
```

## Trust boundary

The signature covers the `signed_hash` text, which is a `sha256:<hex>` digest of the canonicalized document. A successful check means the document content matches a signature made by the registered key. It proves vendor provenance only if the caller has independently authenticated that key and bound it to the expected vendor and document.

- `Verifier::trust(key_url, key)` registers a key supplied by the caller. It does not download or authenticate the URL. Re-registering a URL replaces its key.
- `Verifier::verify` accepts any key in that trust set. For a vendor-specific decision, use `verify_for_key_url(expected_key_url, attestation, body)` with an expected URL obtained independently of the attestation.
- `Attestation::verify(key, body)` checks only the supplied key and body. It does not inspect `key_url`.
- `key_url` and `signed_at` are **not signed**. The timestamp is advisory and cannot establish signing time, freshness, or an audit chronology. This format has no replay protection or key revocation protocol.
- A detached `<doc>.sig.json` record is straightforward. If an attestation is placed inline, pass the original document **without the attestation field** to both `sign` and `verify`; otherwise the document hash changes.
- The hash is over the parsed JSON value, not the original byte stream. Whitespace, object key order, and duplicate object keys in raw JSON are not preserved by typical parsing. Reject duplicate keys before signing or verifying if they are meaningful in your input policy.
- Protect the signing key outside the crate, establish key ownership through an authenticated channel, and define key rotation and revocation policy in the calling system. Fetching a key from the same compromised route as the document does not establish independent provenance.

## Canonical hash compatibility

The current Rust hash format sorts JSON object keys and serializes values without whitespace using `serde_json`, then hashes the resulting UTF-8 bytes. The Ed25519 signature signs the UTF-8 bytes of the resulting `sha256:<hex>` string. This is **not a versioned cross-language canonical JSON specification**.

The `procurement-decision-api` Python implementation currently uses `json.dumps(..., sort_keys=True, separators=(",", ":"))`. Its default Unicode escaping and numeric formatting can produce different hashes for the same parsed JSON:

| JSON value | Rust serialization/hash | Python serialization/hash |
| --- | --- | --- |
| `{"name":"Café"}` | `{"name":"Café"}` / `sha256:659906f125d844f7081786e4a1cba739414e49a9b9061d80ce09c691b5f56602` | `{"name":"Caf\u00e9"}` / `sha256:763d71db1da1bf942dd08dc6ed73b60fd37295c93420be1a16f70017be12f5f8` |
| `{"x":1e-7}` | `{"x":1e-7}` / `sha256:43c8e92bd5552bd45030718eb9366d6d6500623793c248666d77dca01ba337c0` | `{"x":1e-07}` / `sha256:c8b4301d31692cc55fc58ee2d4368e95e4971ac5d25036abceb45c33a05b0fcb` |

Do not claim arbitrary JSON hashes are interchangeable across the Rust and Python services. A future cross-language format needs a versioned canonicalization specification, shared test vectors, and an explicit migration path for existing signed hashes. The current hash behavior stays unchanged for compatibility with published v0.1 attestations.

## Optional audit-stream feature

`audit-stream` adds best-effort event emission to `AUDIT_STREAM_URL` after signing or verification. It sends `attestation_signed`, `attestation_verified`, or `attestation_failed` to `/events`. An outage does not change the cryptographic result, but the call can wait for its configured timeout. `AUDIT_STREAM_TIMEOUT_S` defaults to 2.5 seconds and is capped at 30 seconds. Treat these events as operational telemetry; they do not authenticate the unsigned `signed_at` field.

The optional event includes `key_url`, `signed_hash`, `signed_at`, and the outcome; failed verification also includes an error reason. It does not send the document body or private key. Configure `AUDIT_STREAM_URL` only for an endpoint authorized to receive this metadata.

## Checks and packaging

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -Dwarnings
cargo test --all-targets
cargo test --doc
cargo clippy --features audit-stream --all-targets -- -Dwarnings
cargo test --features audit-stream --all-targets
cargo package --list
```

CI targets stable, beta, and Rust 1.88.0 (MSRV). The `include` allowlist in `Cargo.toml` limits the published crate to source, tests, examples, benches, README, and license plus Cargo-required manifest metadata. A tag-triggered publish workflow reruns checks before a crates.io upload; tagging and publishing are separate release actions.

## License

MIT. See [LICENSE](LICENSE).
