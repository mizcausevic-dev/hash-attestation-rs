//! [`Attestor`] (signer) and [`Verifier`] (trusted-key set).

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::Serialize;

use crate::attestation::Attestation;
use crate::error::AttestationError;
use crate::hash::canonical_hash;

/// Wraps a signing key + the well-known URL the verifier will fetch the
/// matching public key from.
pub struct Attestor {
    key: SigningKey,
    key_url: String,
}

impl Attestor {
    /// Build an attestor.
    pub fn new(key: SigningKey, key_url: String) -> Self {
        Self { key, key_url }
    }

    /// Sign `body` and return an [`Attestation`] that captures the canonical
    /// hash + signature + key URL + timestamp.
    pub fn sign<T: Serialize>(&self, body: &T) -> Result<Attestation, AttestationError> {
        let signed_hash = canonical_hash(body)?;
        let signature = self.key.sign(signed_hash.as_bytes());
        Ok(Attestation::new(
            signed_hash,
            &signature.to_bytes(),
            self.key_url.clone(),
        ))
    }

    /// Return the matching verifying key for handing out alongside published docs.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The key URL this attestor stamps into every attestation.
    pub fn key_url(&self) -> &str {
        &self.key_url
    }

    /// Sign `body`, **and** fire an `attestation_signed` event to the
    /// audit-stream spine. Same semantics as [`Attestor::sign`] — the
    /// emit is best-effort and never blocks the signature.
    ///
    /// Available only with the `audit-stream` feature.
    #[cfg(feature = "audit-stream")]
    pub async fn sign_with_audit<T: Serialize>(
        &self,
        client: &reqwest::Client,
        body: &T,
    ) -> Result<Attestation, AttestationError> {
        let signed = self.sign(body)?;
        crate::audit_stream::emit(
            client,
            "attestation_signed",
            serde_json::json!({
                "key_url": signed.key_url,
                "signed_hash": signed.signed_hash,
                "signed_at": signed.signed_at,
            }),
        )
        .await;
        Ok(signed)
    }
}

/// A trust set — `key_url -> VerifyingKey`. Callers register known keys
/// up-front, then verify attestations by url-lookup.
#[derive(Debug, Default, Clone)]
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
}

impl Verifier {
    /// Empty trust set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a trusted key under its publish URL. Re-registering with the
    /// same URL overwrites the previous key.
    pub fn trust(&mut self, key_url: impl Into<String>, key: VerifyingKey) -> &mut Self {
        self.keys.insert(key_url.into(), key);
        self
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the trust set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verify an attestation. The attestation's `key_url` must match a
    /// previously-trusted key.
    pub fn verify<T: Serialize>(
        &self,
        attestation: &Attestation,
        body: &T,
    ) -> Result<(), AttestationError> {
        let Some(key) = self.keys.get(&attestation.key_url) else {
            return Err(AttestationError::UntrustedKey(attestation.key_url.clone()));
        };
        attestation.verify(key, body)
    }

    /// Verify an attestation **and** fire an `attestation_verified` (or
    /// `attestation_failed`) event to the audit-stream spine. Same
    /// semantics as [`Verifier::verify`] — the emit is best-effort and
    /// never blocks the verification result.
    ///
    /// Available only with the `audit-stream` feature.
    #[cfg(feature = "audit-stream")]
    pub async fn verify_with_audit<T: Serialize>(
        &self,
        client: &reqwest::Client,
        attestation: &Attestation,
        body: &T,
    ) -> Result<(), AttestationError> {
        let outcome = self.verify(attestation, body);
        let (kind, reason) = match &outcome {
            Ok(()) => ("attestation_verified", None),
            Err(err) => ("attestation_failed", Some(err.to_string())),
        };
        let mut payload = serde_json::json!({
            "key_url": attestation.key_url,
            "signed_hash": attestation.signed_hash,
            "signed_at": attestation.signed_at,
            "trusted_keys": self.keys.len(),
        });
        if let Some(r) = reason {
            payload["reason"] = serde_json::Value::String(r);
        }
        crate::audit_stream::emit(client, kind, payload).await;
        outcome
    }
}
