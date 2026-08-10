//! CSRF protection.
//!
//! Uses the signed double-submit cookie pattern from Auth.js: the cookie stores
//! `<token>|<hmac>` where hmac = HMAC-SHA256(token + secret). The same raw token
//! must be echoed in the request body for unsafe (POST) actions.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Signs a CSRF token with the configured secret.
pub fn csrf_hash(token: &str, secret: &str) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(token.as_bytes());
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Validates the signed cookie and that the submitted body token matches.
/// Returns the canonical token and whether validation passed.
pub fn verify_csrf(cookie_value: &str, body_token: &str, secret: &str) -> (String, bool) {
    let Some((token, signature)) = cookie_value.split_once('|') else {
        return (String::new(), false);
    };
    let expected = csrf_hash(token, secret);
    if !bool::from(signature.as_bytes().ct_eq(expected.as_bytes())) {
        return (token.to_string(), false);
    }
    if body_token.is_empty() {
        // The cookie is valid but no body token was submitted (e.g. a GET to
        // fetch the token). Callers decide whether that's acceptable.
        return (token.to_string(), false);
    }
    if !bool::from(body_token.as_bytes().ct_eq(token.as_bytes())) {
        return (token.to_string(), false);
    }
    (token.to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_csrf_accepts_only_matching_signed_pairs() {
        const SECRET: &str = "test-secret";
        const TOKEN: &str = "random-token";
        let cookie = format!("{TOKEN}|{}", csrf_hash(TOKEN, SECRET));

        let cases: &[(&str, &str, &str, bool)] = &[
            ("valid cookie and body", &cookie, TOKEN, true),
            ("body token mismatch", &cookie, "other-token", false),
            ("missing body token", &cookie, "", false),
            ("tampered signature", "random-token|deadbeef", TOKEN, false),
            ("malformed cookie", "no-separator", TOKEN, false),
            ("empty cookie", "", TOKEN, false),
        ];

        for (name, cookie, body, want_valid) in cases {
            let (_, valid) = verify_csrf(cookie, body, SECRET);
            assert_eq!(valid, *want_valid, "{name}");
        }
    }
}
