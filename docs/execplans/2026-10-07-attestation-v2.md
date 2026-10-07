# Attestation v0.2 release plan

## Goal

Produce a reviewable Rust crate that signs and verifies JSON with an explicit cross-language canonicalization profile while continuing to verify published v0.1 attestations.

## Current state

Observed base: commit `9d61356` on `codex/release-review-2026-10-07`. The published v0.1 envelope omits a hash profile, signs only a `sha256:<hex>` text, and uses a Rust-specific JSON representation. The Python buyer API uses another JSON representation, so arbitrary v0.1 hashes diverge for Unicode and number formatting. This crate has an opt-in HTTP audit emitter and a tag-triggered crates.io workflow.

## Scope

Add versioned RFC 8785 JCS signing, raw JSON validation, shared vectors, migration documentation, and release checks. Preserve v0.1 verification and explicit legacy signing. Do not push, tag, publish, deploy, alter GitHub About, or change other repositories.

## Acceptance criteria

- Rust verifies independently generated Python JCS/hash/Ed25519 vectors, including a Decision Card.
- Rust generates the expected deterministic signature for fixed vector metadata.
- Raw JSON entry points reject duplicate keys, unsafe integer literals, and invalid Unicode.
- V0.2 signatures fail if body, key URL, timestamp, algorithm, or profile changes.
- Existing v0.1 serialized attestation verifies and remains distinguishable.
- Formatting, lint, tests, package inspection, supply-chain checks, and live remote check are recorded exactly.

## Risks and release class

R3 cryptographic wire-format migration. Main risks are silent hash divergence, metadata downgrade, lost duplicate keys, untrusted key ownership, and publishing from an unreviewed tag. The release is local-only pending parent cross-repository review. No private keys or customer data are used in fixtures.

## Design

V0.2 uses profile `jcs-rfc8785-v1`, SHA-256 over RFC 8785 UTF-8, and Ed25519 over `hash-attestation/v2` plus a NUL byte plus JCS for the five signed metadata fields. Missing profile selects legacy v0.1 verification only. Raw JSON helpers enforce an I-JSON input boundary before parsing; already parsed values require upstream duplicate-key rejection. An MIT RFC 8785 canonicalizer is necessary because `serde_json` does not use RFC 8785 number formatting or UTF-16 property ordering. A silent replacement of the v0.1 hash was rejected because existing signatures must keep verifying.

## Execution sequence

1. Add the v0.2 profile and preserve legacy verification in `src/`.
2. Add strict raw JSON entry points and numeric/Unicode validation.
3. Add Python/Rust and legacy vectors under `tests/vectors/`.
4. Update README and package version to 0.2.0.
5. Run release checks, review diff and package contents, then commit locally.

## Verification

Run focused vector/input tests; `cargo fmt --all -- --check`; locked clippy and all-target tests for default and `audit-stream`; MSRV test with Rust 1.88.0; package list and dry-run; workflow lint; RustSec scan and license/secret checks; `git diff --check`; live `git ls-remote origin refs/heads/main`.

## Deployment and rollback

No deployment or publication in this task. A later authorized release must merge reviewed code to main, create a matching `v0.2.0` tag on main, let the publish workflow verify/package, then check the crates.io version and docs. Rollback is to stop new v0.2 signing and use the prior crate version; previously issued v0.2 signatures require a v0.2 verifier and must not be relabeled as legacy.

## Progress

- 2026-10-07: v0.2 design implemented; independent Python vectors generated; focused Rust interoperability and input tests passed.
- 2026-10-07: Initial RustSec scan found four vulnerable transitive versions in generated `Cargo.lock`; refreshed the locked graph to patched versions and rescanned successfully. Tracked the lockfile and added locked CI and publish gates.
- 2026-10-07: Full local test, lint, MSRV, package, workflow, and advisory checks completed. No remote publication was attempted.

## Decisions

- Profile field is explicit in the attestation envelope; a bare hash remains ambiguous.
- Legacy verification is retained, while default signing moves to v0.2.
- Key ownership and freshness remain caller responsibilities.
- Track `Cargo.lock` so CI and the publish workflow scan and build the same reviewed dependency versions; consumers resolve their own graph.

## Outcome

Local v0.2 crate is ready for parent cross-repository review. Exact final checks, all exit 0: `cargo fmt --all -- --check`; `cargo clippy --locked --all-targets --offline -- -Dwarnings`; `cargo clippy --locked --features audit-stream --all-targets --offline -- -Dwarnings`; `cargo build --locked --all-targets --offline`; `cargo test --locked --all-targets --offline` (26 tests plus two bench smoke runs); `cargo test --locked --features audit-stream --all-targets --offline` (39 tests plus bench smoke runs); `cargo +1.88.0 test --locked --all-targets --offline` (26 tests plus bench smoke runs); `cargo test --locked --doc --offline` (1 doc test); `actionlint -color=false .github/workflows/ci.yml .github/workflows/publish.yml`; `git diff --check`; RustSec `cargo-audit audit --file Cargo.lock` (223 dependencies, no advisories after update); `cargo publish --dry-run --allow-dirty --locked` (23 files, upload aborted by dry-run). `cargo metadata --format-version 1 --offline` found license metadata on all 173 enumerated packages. `git ls-remote origin refs/heads/main` returned `ef156271ca8246a5028255d22124bbd66f2b669b`.

The initial RustSec scan identified `crossbeam-epoch` 0.9.18, `h2` 0.4.14, `quinn-proto` 0.11.14, and `rustls` 0.23.40; the final lockfile uses 0.9.21, 0.4.20, 0.11.19, and 0.23.45. Secret checks were scoped to the local checkout and are not a guarantee of absence. Hosted GitHub CI, crates.io publication, key ownership, key revocation, independent time evidence, and downstream integrations were not verified. No push, tag, merge, publish, or deploy occurred.
