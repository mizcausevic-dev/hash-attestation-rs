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
    let raw_body = r#"{"aeo_version":"0.1","entity":{"name":"Acme"}}"#;
    let signed: Attestation = attestor.sign_raw_json(raw_body)?;

    // In production, establish this key and its vendor binding through an
    // independently authenticated source. Do not trust a key merely because
    // the attestation supplies a URL for it.
    let mut verifier = Verifier::new();
    verifier.trust(key_url, attestor.verifying_key());
    verifier.verify_raw_json_for_key_url(key_url, &signed, raw_body)?;
    Ok(())
}
```

## Trust boundary

For v0.2 attestations, the signature covers a domain-separated RFC 8785 payload containing `algorithm`, `hash_profile`, `signed_hash`, `key_url`, and `signed_at`. The hash is `sha256:<hex>` over the document's RFC 8785 JSON canonicalization. A successful check means the canonical document and signed metadata match a signature made by the registered key. It proves vendor provenance only if the caller has independently authenticated that key and bound it to the expected vendor and document.

- `Verifier::trust(key_url, key)` registers a key supplied by the caller. It does not download or authenticate the URL. Re-registering a URL replaces its key.
- `Verifier::verify` accepts any key in that trust set. For a vendor-specific decision, use `verify_for_key_url(expected_key_url, attestation, body)` with an expected URL obtained independently of the attestation.
- `Attestation::verify(key, body)` checks the supplied key and body; it has no independently expected vendor or key URL. V0.2 binds the envelope's `key_url` and `signed_at` to its signature. The timestamp is still only a signer assertion, not trusted wall-clock evidence. The crate has no freshness, replay, or key revocation protocol.
- Legacy v0.1 attestations sign only `signed_hash`. Their `key_url` and `signed_at` remain unauthenticated. Do not accept legacy attestations where authenticated metadata or cross-language hash parity is required.
- A detached `<doc>.sig.json` record is straightforward. If an attestation is placed inline, pass the original document **without the attestation field** to both `sign` and `verify`; otherwise the document hash changes.
- The hash is over a JSON value, not the original byte stream. Whitespace and object key order do not affect it. Typical JSON parsers discard duplicate keys, so use `sign_raw_json` and `verify_raw_json_for_key_url` for untrusted JSON text. Those APIs reject duplicate keys, unpaired surrogates, non-finite numbers, and integer literals outside the IEEE-754 safe range before a lossy parse. If you pass an already parsed `serde_json::Value` to `sign` or `verify`, the caller must have enforced these rules before parsing.
- Protect the signing key outside the crate, establish key ownership through an authenticated channel, and define key rotation and revocation policy in the calling system. Fetching a key from the same compromised route as the document does not establish independent provenance.

## Canonical hash profiles and migration

`Attestor::sign` and `sign_raw_json` now create the `jcs-rfc8785-v1` profile. `canonical_hash_jcs` hashes RFC 8785 UTF-8 bytes. For a v0.2 attestation, the Ed25519 signing input is the ASCII bytes `hash-attestation/v2`, one NUL byte, and RFC 8785 UTF-8 bytes of an object with exactly these fields: `algorithm`, `hash_profile`, `key_url`, `signed_at`, `signed_hash`. The `signature` field is excluded. `Attestation::signing_input_v2` exposes those bytes for interoperability tests.

RFC 8785 does not normalize Unicode. New profile inputs must be I-JSON. The raw JSON entry points enforce duplicate-key and safe-integer rules, and reject unpaired surrogates; generic `Serialize` input must be deterministic and cannot recover duplicate keys lost before the call. See the [shared Python/Rust vectors](tests/vectors/jcs-rfc8785-v1.json) and [Decision Card vector](tests/vectors/decision-card-v2.json).

**Migrating from v0.1:** the published legacy `canonical_hash` remains unchanged. `Attestation::verify` accepts old JSON records without `hash_profile` and verifies them using the original hash and signature bytes. Use `Attestor::sign_legacy` only for a planned compatibility transition. New Rust struct literals must include `hash_profile`; ordinary old wire records need no change. The deserializer rejects unknown envelope fields and an explicit `null` profile, so nonstandard legacy records need cleanup first. Treat an omitted profile as legacy, never as an implicit v0.2 signature. This crate version is 0.2.0 because default signing and the public struct changed.

Legacy v0.1 sorts JSON object keys and serializes values without whitespace using `serde_json`, then hashes the resulting UTF-8 bytes. Its Ed25519 signature signs the UTF-8 bytes of the `sha256:<hex>` string. This old format is **not a cross-language canonical JSON specification**.

The `procurement-decision-api` Python implementation currently uses `json.dumps(..., sort_keys=True, separators=(",", ":"))`. Its default Unicode escaping and numeric formatting can produce different hashes for the same parsed JSON:

| JSON value | Rust serialization/hash | Python serialization/hash |
| --- | --- | --- |
| `{"name":"Café"}` | `{"name":"Café"}` / `sha256:659906f125d844f7081786e4a1cba739414e49a9b9061d80ce09c691b5f56602` | `{"name":"Caf\u00e9"}` / `sha256:763d71db1da1bf942dd08dc6ed73b60fd37295c93420be1a16f70017be12f5f8` |
| `{"x":1e-7}` | `{"x":1e-7}` / `sha256:43c8e92bd5552bd45030718eb9366d6d6500623793c248666d77dca01ba337c0` | `{"x":1e-07}` / `sha256:c8b4301d31692cc55fc58ee2d4368e95e4971ac5d25036abceb45c33a05b0fcb` |

The table describes only legacy v0.1. New v0.2 interoperability is proven for the checked vectors, including Unicode, exponent formatting, negative zero, UTF-16 key ordering, and a signed Decision Card. Consumers must carry the profile identifier with the hash. A bare `sha256:<hex>` string cannot identify which canonicalization produced it.

## Optional audit-stream feature

`audit-stream` adds best-effort event emission to `AUDIT_STREAM_URL` after signing or verification. It sends `attestation_signed`, `attestation_verified`, or `attestation_failed` to `/events`. An outage does not change the cryptographic result, but the call can wait for its configured timeout. `AUDIT_STREAM_TIMEOUT_S` defaults to 2.5 seconds and is capped at 30 seconds. Treat these events as operational telemetry; they do not establish trusted wall-clock signing time.

The optional event includes `key_url`, `signed_hash`, `signed_at`, and the outcome; failed verification also includes an error reason. It does not send the document body or private key. Configure `AUDIT_STREAM_URL` only for an endpoint authorized to receive this metadata. These events do not add trusted timing or identity evidence to either signature profile.

## Checks and packaging

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -Dwarnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo clippy --locked --features audit-stream --all-targets -- -Dwarnings
cargo test --locked --features audit-stream --all-targets
cargo audit --file Cargo.lock
cargo package --locked --list
```

CI targets stable, beta, and Rust 1.88.0 (MSRV). The tracked `Cargo.lock` pins the review and publishing dependency graph; downstream applications still resolve their own dependencies. The `include` allowlist in `Cargo.toml` limits the published crate to source, tests and shared vectors, examples, benches, README, and license plus Cargo-generated manifest and lockfile metadata. CI and tag-triggered publishing run a RustSec advisory scan against the locked graph. Tagging and publishing are separate release actions.

## License

MIT. See [LICENSE](LICENSE).
