//! # hash-attestation
//!
//! **Sign and verify Kinetic Gain Protocol Suite documents** using ed25519
//! signatures over the same canonical-hash convention every other Suite
//! repo already uses (`sha256:<hex>` over sorted-keys, no-whitespace JSON).
//!
//! ## The missing layer
//!
//! Right now a consumer fetches an AEO doc (or agent-card, or decision-card)
//! over HTTPS and trusts that the bytes came from the published origin. That
//! works for typo-grade tampering but breaks the moment a CDN is misconfigured
//! or an MITM lands. This crate adds a detached-signature layer: vendors sign
//! the canonical hash with an ed25519 private key, publish the public key at a
//! well-known URL, and consumers verify the [`Attestation`] before they trust
//! the doc.
//!
//! ## At-a-glance
//!
//! ```
//! use hash_attestation::{Attestation, Attestor, canonical_hash};
//! use ed25519_dalek::SigningKey;
//! use rand_core::OsRng;
//!
//! let key = SigningKey::generate(&mut OsRng);
//! let attestor = Attestor::new(key.clone(), "https://acme.example/keys/aeo".to_string());
//!
//! let body = serde_json::json!({
//!     "aeo_version": "0.1",
//!     "entity": { "id": "https://acme.example/#org", "name": "Acme" }
//! });
//!
//! let signed: Attestation = attestor.sign(&body).unwrap();
//! assert!(signed.verify(&key.verifying_key(), &body).is_ok());
//! ```
//!
//! ## What's in the box
//!
//! - [`canonical_hash`] — `sha256:<hex>` over canonical JSON. Same convention
//!   as `procurement-decision-api` + `aeo-validator-service`.
//! - [`Attestor`] — wraps a `SigningKey` with the key URL so calls always
//!   produce a self-describing [`Attestation`].
//! - [`Attestation`] — serde-serialisable signature record. Drop it next to
//!   the source doc as `<doc>.sig.json`, or include it inline.
//! - [`Verifier`] — convenience for verifying with a list of trusted keys.
//!
//! ## Composes with
//!
//! - **[aeo-validator-service](https://github.com/mizcausevic-dev/aeo-validator-service)**
//!   — verifies the attestation alongside its drift check; mismatches surface
//!   as a top-level `Attestation::Tampered` issue.
//! - **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)**
//!   — every published Decision Card can be paired with a signature so policy
//!   bundles can prove provenance.
//! - **[aeo-crawler](https://github.com/mizcausevic-dev/aeo-crawler)** — emits
//!   the canonical hash for every fetched doc, ready for offline verification.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

pub mod attestation;
pub mod attestor;
pub mod error;
pub mod hash;

/// Optional audit-stream-py producer. Gated behind the `audit-stream`
/// Cargo feature so the core crypto crate stays sync and HTTP-free.
#[cfg(feature = "audit-stream")]
pub mod audit_stream;

pub use attestation::Attestation;
pub use attestor::Attestor;
pub use error::AttestationError;
pub use hash::canonical_hash;

// Verifier holds a small set of trusted keys.
pub use attestor::Verifier;
