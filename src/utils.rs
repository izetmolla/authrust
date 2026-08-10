//! Shared helpers: path matching, Redis key/value plumbing, signing-method
//! resolution and the package's custom duration format.

use std::time::Duration;

use jsonwebtoken::Algorithm;
use serde_json::{Map as JsonMap, Value};

use crate::constants::DEFAULT_REDIS_PREFIX;
use crate::errors::{Error, Result};
use crate::session::SessionData;
use crate::user::User;

/// Reports whether `path` starts with any prefix in `excluded`. Prefix matching
/// is intentional so callers can opt entire route trees out of authentication
/// (e.g. `/api/public`).
pub fn is_excluded_path(excluded: &[String], path: &str) -> bool {
    excluded
        .iter()
        .any(|prefix| !prefix.is_empty() && path.starts_with(prefix.as_str()))
}

/// Validates session data for required fields.
pub fn validate_session_data(session: &SessionData) -> Result<()> {
    if session.id.is_empty() {
        return Err(Error::msg("session ID cannot be empty"));
    }
    if session.user_id.is_empty() {
        return Err(Error::msg("user ID cannot be empty"));
    }
    Ok(())
}

/// Creates a Redis key with the configured prefix.
pub fn build_redis_key(prefix: &str, session_id: &str) -> String {
    let prefix = if prefix.is_empty() {
        DEFAULT_REDIS_PREFIX
    } else {
        prefix
    };
    format!("{prefix}:{session_id}")
}

/// Serializes session data to JSON for Redis storage.
pub fn serialize_session_data(session: &SessionData) -> Result<String> {
    serde_json::to_string(session)
        .map_err(|err| Error::msg(format!("failed to marshal session data: {err}")))
}

/// Deserializes JSON data from Redis into session data.
pub fn deserialize_session_data(data: &str) -> Result<SessionData> {
    if data.is_empty() {
        return Err(Error::msg("session data is empty"));
    }
    let session: SessionData = serde_json::from_str(data)
        .map_err(|err| Error::msg(format!("failed to unmarshal session data: {err}")))?;
    validate_session_data(&session)?;
    Ok(session)
}

/// Maps a configured signing-method name onto a JWT algorithm, defaulting to
/// HS256 for empty or unrecognised values.
pub fn resolve_signing_method(method: &str) -> Algorithm {
    match method.to_lowercase().as_str() {
        "hs384" => Algorithm::HS384,
        "hs512" => Algorithm::HS512,
        _ => Algorithm::HS256,
    }
}

/// Parses values such as `30s`, `15m`, `1h`, `7d`, `4w`, `1mo` or `1y`. The
/// empty string falls back to `default_input`.
pub fn parse_custom_duration(input: &str, default_input: &str) -> Result<Duration> {
    let input = if input.is_empty() {
        default_input
    } else {
        input
    };

    let split_at = input
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(input.len());
    if split_at == 0 {
        return Err(Error::msg("invalid duration: missing number"));
    }

    let num: u64 = input[..split_at]
        .parse()
        .map_err(|err| Error::msg(format!("invalid number: {err}")))?;

    let unit = &input[split_at..];
    let multiplier = match unit {
        "s" => Duration::from_secs(1),
        "m" => Duration::from_secs(60),
        "h" => Duration::from_secs(60 * 60),
        "d" => Duration::from_secs(24 * 60 * 60),
        "w" => Duration::from_secs(7 * 24 * 60 * 60),
        // approximate month
        "mo" => Duration::from_secs(30 * 24 * 60 * 60),
        // approximate year
        "y" => Duration::from_secs(365 * 24 * 60 * 60),
        other => return Err(Error::msg(format!("invalid time unit: {other:?}"))),
    };

    Ok(multiplier * num as u32)
}

/// Renders a duration the way Go's `time.Duration.String` does, e.g. `5m0s` or
/// `8760h0m0s`. The `tokenlife` claim uses this format, so tokens stay readable
/// by the Go implementation of this package.
pub fn go_duration_string(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos == 0 {
        return "0s".to_string();
    }
    if nanos < 1_000_000_000 {
        let (value, unit) = if nanos < 1_000 {
            (nanos as f64, "ns")
        } else if nanos < 1_000_000 {
            (nanos as f64 / 1_000.0, "µs")
        } else {
            (nanos as f64 / 1_000_000.0, "ms")
        };
        return format!("{}{}", trim_float(value), unit);
    }

    let secs = d.as_secs();
    let frac = {
        let sub = d.subsec_nanos();
        if sub == 0 {
            String::new()
        } else {
            format!(".{}", format!("{sub:09}").trim_end_matches('0'))
        }
    };
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = secs / 3600;

    if h > 0 {
        format!("{h}h{m}m{s}{frac}s")
    } else if m > 0 {
        format!("{m}m{s}{frac}s")
    } else {
        format!("{s}{frac}s")
    }
}

fn trim_float(value: f64) -> String {
    let s = format!("{value:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_string()
}

/// Safely extracts a string value from a decoded claim set.
pub fn string_claim(claims: &JsonMap<String, Value>, key: &str) -> String {
    match claims.get(key) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Renders a user for the callback page and JSON responses: `id` and `roles`
/// plus any extra fields the application attached in `User::user`.
pub fn format_user(user: Option<&User>) -> Value {
    let Some(user) = user else {
        return Value::Object(JsonMap::new());
    };
    let mut formatted = JsonMap::new();
    formatted.insert("id".to_string(), Value::String(user.id.clone()));
    formatted.insert("roles".to_string(), user.roles.to_value());
    if let Some(extra) = &user.user {
        for (key, value) in extra.iter() {
            formatted.insert(key.clone(), value.clone());
        }
    }
    Value::Object(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_custom_duration_units() {
        let cases: &[(&str, &str, Duration)] = &[
            ("30s", "", Duration::from_secs(30)),
            ("15m", "", Duration::from_secs(15 * 60)),
            ("1h", "", Duration::from_secs(3600)),
            ("7d", "", Duration::from_secs(7 * 24 * 3600)),
            ("4w", "", Duration::from_secs(4 * 7 * 24 * 3600)),
            ("1mo", "", Duration::from_secs(30 * 24 * 3600)),
            ("1y", "", Duration::from_secs(365 * 24 * 3600)),
            ("", "60s", Duration::from_secs(60)),
        ];
        for (input, default_input, want) in cases {
            let got = parse_custom_duration(input, default_input)
                .unwrap_or_else(|err| panic!("parse_custom_duration({input:?}): {err}"));
            assert_eq!(got, *want, "parse_custom_duration({input:?})");
        }
    }

    #[test]
    fn parse_custom_duration_errors() {
        for (input, default_input) in [("d", ""), ("10x", ""), ("", "")] {
            assert!(
                parse_custom_duration(input, default_input).is_err(),
                "expected error for {input:?}"
            );
        }
    }

    #[test]
    fn is_excluded_path_matches_prefixes() {
        let public = vec!["/public".to_string()];
        assert!(is_excluded_path(&public, "/public"));
        assert!(is_excluded_path(&public, "/public/health"));
        assert!(!is_excluded_path(&public, "/private"));
        assert!(!is_excluded_path(&[String::new()], "/anything"));
        assert!(!is_excluded_path(&[], "/anything"));
    }

    #[test]
    fn go_duration_string_matches_go_format() {
        assert_eq!(go_duration_string(Duration::from_secs(300)), "5m0s");
        assert_eq!(go_duration_string(Duration::from_secs(60)), "1m0s");
        assert_eq!(go_duration_string(Duration::from_secs(30)), "30s");
        assert_eq!(go_duration_string(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(
            go_duration_string(Duration::from_secs(365 * 24 * 3600)),
            "8760h0m0s"
        );
    }
}
