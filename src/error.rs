//! Crate-wide error type.

use thiserror::Error;

/// Anything that can go wrong inside the crate.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// Serialising the input doc to canonical JSON failed.
    #[error("failed to canonicalise input: {0}")]
    Canonical(#[from] serde_json::Error),

    /// `signed_hash` didn't match the recomputed canonical hash for the body
    /// supplied at verify time.
    #[error("attestation hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Hash recorded on the attestation.
        expected: String,
        /// Hash recomputed from the body the caller supplied.
        actual: String,
    },

    /// Signature didn't validate against the public key.
    #[error("ed25519 signature is invalid")]
    BadSignature,

    /// Base64 decoding the signature field failed.
    #[error("signature is not valid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// Signature bytes weren't 64 bytes after decode.
    #[error("signature must be 64 bytes after base64-decode; got {0}")]
    WrongSignatureLength(usize),

    /// The attestation declared `algorithm` we don't know how to verify.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The caller asked [`crate::Verifier::verify`] for a key URL that
    /// wasn't in the trust set.
    #[error("untrusted key URL: {0}")]
    UntrustedKey(String),
}
