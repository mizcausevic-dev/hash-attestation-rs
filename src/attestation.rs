//! The [`Attestation`] envelope — a self-describing signature record.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::AttestationError;
use crate::hash::{canonical_hash, canonical_hash_jcs, parse_jcs_json_strict};

/// RFC 8785 JSON hash profile used by v0.2 attestations.
pub const JCS_HASH_PROFILE: &str = "jcs-rfc8785-v1";

const V2_DOMAIN: &[u8] = b"hash-attestation/v2\0";

/// Signature record. JSON-serialisable so callers can drop it next to the
/// source doc as `<doc>.sig.json` or fold it into the doc body.
///
/// Fields:
///
/// - `algorithm` — frozen as `"ed25519"` for both supported formats.
/// - `hash_profile` — `"jcs-rfc8785-v1"` for new signatures, absent for legacy v0.1.
/// - `signed_hash` — the canonical hash of the body at signing.
/// - `signature` — base64-encoded 64-byte Ed25519 signature.
/// - `key_url` — a key selector, not a trusted key discovery mechanism.
/// - `signed_at` — UTC timestamp asserted by the signer.
///
/// Legacy v0.1 signatures cover only `signed_hash`. V0.2 signatures cover
/// algorithm, profile, hash, key URL, and timestamp in a domain-separated
/// RFC 8785 payload. Neither format independently proves vendor identity or
/// wall-clock signing time. Establish the expected key and vendor separately.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// The signature algorithm. Frozen as `"ed25519"` for both formats.
    pub algorithm: String,
    /// Canonical hash profile. Missing means the legacy v0.1 format.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_profile"
    )]
    pub hash_profile: Option<String>,
    /// Canonical hash of the body at signing time (`sha256:<hex>`).
    pub signed_hash: String,
    /// Base64-encoded 64-byte Ed25519 signature.
    pub signature: String,
    /// Public key URL selector. The verifier must establish trust separately.
    pub key_url: String,
    /// UTC timestamp asserted by the signer. Signed only in the v0.2 format.
    pub signed_at: String,
}

fn deserialize_profile<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(Some(String::deserialize(deserializer)?))
}

impl Attestation {
    /// Construct a legacy v0.1 attestation from raw parts. This preserves
    /// the published constructor; new callers should use [`crate::Attestor::sign`].
    pub fn new(signed_hash: String, signature_bytes: &[u8], key_url: String) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            hash_profile: None,
            signed_hash,
            signature: B64.encode(signature_bytes),
            key_url,
            signed_at: now_iso(),
        }
    }

    pub(crate) fn new_v2(signed_hash: String, key_url: String) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            hash_profile: Some(JCS_HASH_PROFILE.to_string()),
            signed_hash,
            signature: String::new(),
            key_url,
            signed_at: now_iso(),
        }
    }

    pub(crate) fn set_signature(&mut self, signature_bytes: &[u8]) {
        self.signature = B64.encode(signature_bytes);
    }

    /// Return the v0.2 bytes signed by Ed25519: the ASCII domain prefix
    /// `hash-attestation/v2`, one NUL byte, then RFC 8785 JCS UTF-8 for the
    /// algorithm, hash profile, key URL, timestamp, and signed hash fields.
    /// The signature field itself is excluded.
    pub fn signing_input_v2(&self) -> Result<Vec<u8>, AttestationError> {
        let profile = self
            .hash_profile
            .as_deref()
            .ok_or_else(|| AttestationError::UnsupportedHashProfile("missing".to_string()))?;
        let payload = serde_json::json!({
            "algorithm": self.algorithm,
            "hash_profile": profile,
            "signed_hash": self.signed_hash,
            "key_url": self.key_url,
            "signed_at": self.signed_at,
        });
        let mut bytes = V2_DOMAIN.to_vec();
        bytes.extend(serde_json_canonicalizer::to_vec(&payload)?);
        Ok(bytes)
    }

    /// Verify this attestation against the body it was meant to sign, using
    /// the caller-supplied key. This method does not prove which vendor owns
    /// the key. V0.2 verifies signed metadata; legacy v0.1 does not.
    pub fn verify<T: Serialize>(
        &self,
        verifying_key: &VerifyingKey,
        body: &T,
    ) -> Result<(), AttestationError> {
        if self.algorithm != "ed25519" {
            return Err(AttestationError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }
        let actual = match self.hash_profile.as_deref() {
            None => canonical_hash(body)?,
            Some(JCS_HASH_PROFILE) => canonical_hash_jcs(body)?,
            Some(other) => {
                return Err(AttestationError::UnsupportedHashProfile(other.to_string()));
            }
        };
        if actual != self.signed_hash {
            return Err(AttestationError::HashMismatch {
                expected: self.signed_hash.clone(),
                actual,
            });
        }
        let bytes = B64.decode(&self.signature)?;
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(AttestationError::WrongSignatureLength(bytes.len()));
        }
        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(&bytes);
        let sig = Signature::from_bytes(&arr);
        let signing_input = if self.hash_profile.is_some() {
            self.signing_input_v2()?
        } else {
            self.signed_hash.as_bytes().to_vec()
        };
        verifying_key
            .verify(&signing_input, &sig)
            .map_err(|_| AttestationError::BadSignature)
    }

    /// Strictly parse an untrusted JSON body before verifying. This rejects
    /// duplicate keys and unsafe integer literals before they can be lost in
    /// an ordinary `serde_json::Value` parse.
    pub fn verify_raw_json(
        &self,
        verifying_key: &VerifyingKey,
        raw_body: &str,
    ) -> Result<(), AttestationError> {
        let body = parse_jcs_json_strict(raw_body)?;
        self.verify(verifying_key, &body)
    }
}

fn now_iso() -> String {
    // RFC-3339-ish — UNIX seconds rendered as a Z-suffixed Zulu time. We avoid
    // `chrono` to keep the dep tree tight.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    jiffy::format_utc(secs)
}

/// Tiny inline RFC-3339 formatter for UNIX seconds — avoids pulling in `chrono`
/// for a 30-line task. Algorithm: standard civil-from-days conversion.
mod jiffy {
    pub(super) fn format_utc(secs: u64) -> String {
        let days = (secs / 86_400) as i64;
        let mut rem = secs % 86_400;
        let hh = rem / 3600;
        rem %= 3600;
        let mm = rem / 60;
        let ss = rem % 60;
        let (y, mo, d) = civil_from_days(days + 719_468);
        format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }

    // Algorithm from Howard Hinnant, https://howardhinnant.github.io/date_algorithms.html
    fn civil_from_days(z: i64) -> (i32, u32, u32) {
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as u64; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let y = if m <= 2 { y + 1 } else { y };
        (y as i32, m, d)
    }
}
