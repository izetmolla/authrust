//! OAuth security checks: random values, PKCE challenges and per-provider
//! check selection.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::provider::{Check, OAuthProvider};

/// Returns a URL-safe random string with the given number of bytes of entropy.
pub fn random_string(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Derives the S256 code challenge for a verifier, per RFC 7636.
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Reports whether an OAuth provider requested a given check.
pub fn provider_uses_check(p: &OAuthProvider, check: Check) -> bool {
    p.checks.contains(&check)
}
