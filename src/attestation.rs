//! The [`Attestation`] envelope — a self-describing signature record.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::error::AttestationError;
use crate::hash::canonical_hash;

/// Signature record. JSON-serialisable so callers can drop it next to the
/// source doc as `<doc>.sig.json` or fold it into the doc body.
///
/// Fields:
///
/// - `algorithm` — frozen as `"ed25519"` for v0.1.
/// - `signed_hash` — the canonical hash of the body at the time of signing.
/// - `signature` — base64-encoded 64-byte ed25519 signature over `signed_hash`.
/// - `key_url` — well-known URL where the verifier can fetch the public key.
/// - `signed_at` — RFC-3339-ish UTC timestamp string.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Attestation {
    /// The signature algorithm. Frozen as `"ed25519"` for v0.1.
    pub algorithm: String,
    /// Canonical hash of the body at signing time (`sha256:<hex>`).
    pub signed_hash: String,
    /// Base64-encoded 64-byte ed25519 signature over `signed_hash` (as UTF-8 bytes).
    pub signature: String,
    /// Public key URL the verifier should trust.
    pub key_url: String,
    /// UTC timestamp the signature was minted.
    pub signed_at: String,
}

impl Attestation {
    /// Construct an attestation from raw parts. Mostly used internally by
    /// [`crate::Attestor::sign`] — callers should prefer that.
    pub fn new(signed_hash: String, signature_bytes: &[u8], key_url: String) -> Self {
        Self {
            algorithm: "ed25519".to_string(),
            signed_hash,
            signature: B64.encode(signature_bytes),
            key_url,
            signed_at: now_iso(),
        }
    }

    /// Verify this attestation against the body it was meant to sign.
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
        let actual = canonical_hash(body)?;
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
        verifying_key
            .verify(self.signed_hash.as_bytes(), &sig)
            .map_err(|_| AttestationError::BadSignature)
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
