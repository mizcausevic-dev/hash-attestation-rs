# hash-attestation

[![CI](https://github.com/mizcausevic-dev/hash-attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/hash-attestation-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Sign and verify Kinetic Gain Protocol Suite documents** using ed25519 signatures over the same canonical-hash convention every other Suite repo already uses (`sha256:<hex>` over sorted-keys, no-whitespace JSON).

The missing "this AEO actually came from the vendor" layer.

```rust
use hash_attestation::{Attestation, Attestor};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

let key = SigningKey::generate(&mut OsRng);
let attestor = Attestor::new(key.clone(), "https://acme.example/keys/aeo".to_string());

let body = serde_json::json!({
    "aeo_version": "0.1",
    "entity": { "id": "https://acme.example/#org", "name": "Acme" }
});

let signed: Attestation = attestor.sign(&body)?;
assert!(signed.verify(&key.verifying_key(), &body).is_ok());
# Ok::<_, hash_attestation::AttestationError>(())
```

---

## Why

Today a consumer fetches an AEO doc (or agent-card, or decision-card) over HTTPS and trusts the bytes came from the published origin. That covers typo-grade tampering and not much else: a misconfigured CDN, a route hijack, a developer with write access who shouldn't have had it — none of them are visible to the consumer.

This crate adds a **detached signature layer**:

1. The vendor signs the canonical hash with an ed25519 private key.
2. The signature + key URL ride alongside the doc (or inline in it).
3. The vendor publishes the matching public key at a well-known URL.
4. The consumer fetches the doc, recomputes the hash, fetches the public key, and verifies.

The signature commits to the **canonical hash**, not the bytes the consumer received. So whitespace, key ordering, and CDN re-encoding don't break verification — but a single character change inside any field does.

---

## What's in the box

| Type | Purpose |
| --- | --- |
| `canonical_hash` | `sha256:<hex>` over canonical JSON. Identical convention to `procurement-decision-api` + `aeo-validator-service` — same input bytes, same hash, across the portfolio. |
| `Attestor` | Wraps a `SigningKey` with the public key URL so every produced `Attestation` is self-describing. |
| `Attestation` | Serde-serialisable envelope: `algorithm`, `signed_hash`, `signature` (base64 ed25519), `key_url`, `signed_at`. Drop it next to the doc as `<doc>.sig.json` or fold it inline. |
| `Verifier` | A trust set — `key_url -> VerifyingKey`. Register keys up-front, verify by URL lookup. |

---

## End-to-end shape

```text
vendor side                                  consumer side
-----------                                  -------------
SigningKey                                   Verifier (trust set)
   │                                            │
   ▼                                            ▼
Attestor::new(key, key_url)                  Verifier::trust(key_url, public_key)
   │                                            ▲
   ▼                                            │
.sign(doc) → Attestation ───── published ─────► .verify(attestation, doc)
                                                returns Ok or AttestationError
```

When a `Verifier::verify` call returns:

- `Ok(())` — the doc is unmodified vs. the moment the vendor signed it AND the signature checks out against the trusted public key.
- `Err(HashMismatch { … })` — the doc has changed since it was signed.
- `Err(BadSignature)` — the signature doesn't match the key.
- `Err(UntrustedKey(…))` — the `key_url` in the attestation isn't in your trust set.
- `Err(UnsupportedAlgorithm(…))` — v0.1 only knows ed25519.

---

## Composes with

- **[aeo-validator-service](https://github.com/mizcausevic-dev/aeo-validator-service)** — verifies the attestation alongside drift; tamper events surface as a structured issue.
- **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** — every Decision Card can be paired with a signature so downstream policy bundles can prove provenance.
- **[aeo-graph-explorer-rs](https://github.com/mizcausevic-dev/aeo-graph-explorer-rs)** — same canonical-hash convention means the explorer's `content_hash` field is what this crate signs.
- **[incident-correlation-rs](https://github.com/mizcausevic-dev/incident-correlation-rs)** — if an `IncidentCard` flags "we don't trust this vendor's AEO anymore", removing the vendor's `key_url` from the verifier is one atomic update away.

---

## Algorithm note

v0.1 is ed25519-only. The algorithm field is included on every attestation so a future v0.2 can add (e.g.) ECDSA-P256 without breaking existing verifiers. Unknown algorithms fail closed.

---

## Bench

```bash
cargo bench
```

Bundled bench measures `sign` and `verify` separately so you can spot regressions in either path.

---

## Tests

```bash
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -Dwarnings
cargo fmt --all -- --check
```

CI matrix: `stable`, `beta`, `1.86.0` (MSRV).

---

## License

MIT. See [LICENSE](LICENSE).
