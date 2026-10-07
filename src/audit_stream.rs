//! Optional audit-stream-py producer.
//!
//! When the `audit-stream` Cargo feature is enabled **and** the
//! `AUDIT_STREAM_URL` env var is set, callers can fire governance events
//! every time an attestation is produced or checked — so signature
//! activity lands in the same hash-chained log that holds the rest of
//! the suite's governance events.
//!
//! Same opt-in pattern as the other Rust producers (incident-correlation,
//! aeo-graph-explorer) and the four Python producers. Identical env-var
//! contract:
//!
//! - `AUDIT_STREAM_URL`        — base URL, e.g. `http://audit.local:8093`
//! - `AUDIT_STREAM_TIMEOUT_S`  — per-call timeout, default 2.5s
//!
//! Best-effort. Failures are logged to stderr and swallowed. An outage does
//! not change the verification result, but can delay it until the timeout.

use std::env;
use std::time::Duration;

use serde_json::json;

/// Default per-call timeout when `AUDIT_STREAM_TIMEOUT_S` is unset.
pub const DEFAULT_TIMEOUT_S: f64 = 2.5;

/// Maximum configured timeout, so bad configuration cannot stall calls
/// indefinitely or overflow `Duration`.
pub const MAX_TIMEOUT_S: f64 = 30.0;

/// True when `AUDIT_STREAM_URL` is set to a non-empty value.
#[must_use]
pub fn is_enabled() -> bool {
    base_url().is_some()
}

/// Stripped audit-stream base URL, or `None` when disabled.
#[must_use]
pub fn base_url() -> Option<String> {
    let raw = env::var("AUDIT_STREAM_URL").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.trim_end_matches('/').to_string())
}

/// Configured per-call timeout. Defaults to 2.5 seconds and clamps finite
/// values to the 0.1-30 second range. Invalid or non-finite values use the
/// default.
#[must_use]
pub fn timeout() -> Duration {
    let secs = env::var("AUDIT_STREAM_TIMEOUT_S")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .map_or(DEFAULT_TIMEOUT_S, |v| v.clamp(0.1, MAX_TIMEOUT_S));
    Duration::from_secs_f64(secs)
}

/// Fire one event. Silent no-op when `AUDIT_STREAM_URL` is unset.
///
/// Failures (connection refused, HTTP 5xx, timeout, malformed URL) are
/// logged to stderr without printing the configured URL, then swallowed.
pub async fn emit(client: &reqwest::Client, kind: &str, payload: serde_json::Value) {
    let Some(url) = base_url() else {
        return;
    };
    let body = json!({
        "kind": kind,
        "source": "hash-attestation",
        "payload": payload,
    });
    let endpoint = format!("{url}/events");
    let result = client
        .post(&endpoint)
        .json(&body)
        .timeout(timeout())
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            eprintln!(
                "audit-stream emit failed (kind={kind}): HTTP {}",
                resp.status()
            );
        }
        Err(err) => {
            let reason = if err.is_timeout() {
                "timeout"
            } else {
                "request error"
            };
            eprintln!("audit-stream emit failed (kind={kind}): {reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn reset_env() {
        env::remove_var("AUDIT_STREAM_URL");
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn disabled_when_unset() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        assert!(!is_enabled());
        assert!(base_url().is_none());
    }

    #[test]
    fn disabled_when_blank() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "   ");
        assert!(!is_enabled());
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn enabled_with_value() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "http://audit.local:8093");
        assert!(is_enabled());
        assert_eq!(base_url().unwrap(), "http://audit.local:8093");
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn trailing_slash_stripped() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_URL", "http://audit.local:8093/");
        assert_eq!(base_url().unwrap(), "http://audit.local:8093");
        env::remove_var("AUDIT_STREAM_URL");
    }

    #[test]
    fn timeout_default() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
    }

    #[test]
    fn timeout_override() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "5.0");
        assert_eq!(timeout(), Duration::from_secs_f64(5.0));
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn timeout_rejects_non_finite_or_invalid_values() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        for raw in ["NaN", "inf", "not-a-number"] {
            env::set_var("AUDIT_STREAM_TIMEOUT_S", raw);
            assert_eq!(timeout(), Duration::from_secs_f64(DEFAULT_TIMEOUT_S));
        }
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }

    #[test]
    fn timeout_clamps_out_of_range_values() {
        let _l = ENV_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_env();
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "-10");
        assert_eq!(timeout(), Duration::from_millis(100));
        env::set_var("AUDIT_STREAM_TIMEOUT_S", "1e300");
        assert_eq!(timeout(), Duration::from_secs_f64(MAX_TIMEOUT_S));
        env::remove_var("AUDIT_STREAM_TIMEOUT_S");
    }
}
