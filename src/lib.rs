//! # hash-attestation
//!
//! Sign JSON document hashes with Ed25519 and verify them against a public
//! key the caller already trusts. The crate does not establish vendor identity
//! or fetch keys. See the README for key binding, unsigned metadata, and
//! cross-language canonicalization limits.
//!
//! ```
//! use hash_attestation::{Attestation, Attestor, Verifier};
//! use ed25519_dalek::SigningKey;
//! use rand_core::OsRng;
//!
//! let key = SigningKey::generate(&mut OsRng);
//! let key_url = "https://acme.example/keys/aeo";
//! let attestor = Attestor::new(key, key_url.to_string());
//! let body = serde_json::json!({"aeo_version": "0.1", "entity": {"name": "Acme"}});
//! let signed: Attestation = attestor.sign(&body).unwrap();
//!
//! let mut verifier = Verifier::new();
//! verifier.trust(key_url, attestor.verifying_key());
//! assert!(verifier.verify_for_key_url(key_url, &signed, &body).is_ok());
//! ```

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
pub use attestor::Verifier;
pub use error::AttestationError;
pub use hash::canonical_hash;
