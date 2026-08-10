//! PBKDF2-SHA256 password hashing for credentials storage.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::errors::{Error, Result};

const PASSWORD_SALT_BYTES: usize = 16;
const PASSWORD_KEY_BYTES: usize = 32;
const PASSWORD_ITERATIONS: u32 = 600_000;
const PASSWORD_HASH_PREFIX: &str = "$pbkdf2-sha256$";
const PASSWORD_HASH_SEGMENTS: usize = 3;
const SHA256_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Returns a PBKDF2-SHA256 hash of `password` suitable for database storage.
/// The encoded form is self-describing:
///
/// ```text
/// $pbkdf2-sha256$<iterations>$<salt>$<hash>
/// ```
///
/// Salt and hash segments use base64 raw URL encoding (no padding).
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; PASSWORD_SALT_BYTES];
    rand::fill(&mut salt[..]);
    Ok(encode_password_hash(PASSWORD_ITERATIONS, &salt, password))
}

/// Reports whether `password` matches a hash produced by [`hash_password`].
pub fn check_password(hash: &str, password: &str) -> bool {
    let Ok((iterations, salt, want)) = decode_password_hash(hash) else {
        return false;
    };
    let got = pbkdf2_sha256(password.as_bytes(), &salt, iterations, want.len());
    bool::from(got.ct_eq(&want))
}

fn encode_password_hash(iterations: u32, salt: &[u8], password: &str) -> String {
    let key = pbkdf2_sha256(password.as_bytes(), salt, iterations, PASSWORD_KEY_BYTES);
    format!(
        "{}{}${}${}",
        PASSWORD_HASH_PREFIX,
        iterations,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(key),
    )
}

fn decode_password_hash(hash: &str) -> Result<(u32, Vec<u8>, Vec<u8>)> {
    let Some(rest) = hash.strip_prefix(PASSWORD_HASH_PREFIX) else {
        return Err(Error::msg("authrust: unknown password hash format"));
    };
    let parts: Vec<&str> = rest.split('$').collect();
    if parts.len() != PASSWORD_HASH_SEGMENTS {
        return Err(Error::msg("authrust: malformed password hash"));
    }
    let iterations: u32 = parts[0]
        .parse()
        .map_err(|_| Error::msg("authrust: invalid password hash iterations"))?;
    if iterations == 0 {
        return Err(Error::msg("authrust: invalid password hash iterations"));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Error::msg("authrust: invalid password hash salt"))?;
    let key = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| Error::msg("authrust: invalid password hash digest"))?;
    Ok((iterations, salt, key))
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let prf = |key: &[u8], msg: &[u8]| -> [u8; SHA256_SIZE] {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(msg);
        mac.finalize().into_bytes().into()
    };

    let num_blocks = key_len.div_ceil(SHA256_SIZE);
    let mut out = Vec::with_capacity(num_blocks * SHA256_SIZE);
    for block in 1..=num_blocks as u32 {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());

        let mut u = prf(password, &msg);
        let mut t = u;
        for _ in 1..iterations {
            u = prf(password, &u);
            for (dst, src) in t.iter_mut().zip(u.iter()) {
                *dst ^= src;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(key_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let hash = hash_password("s3cret-password").expect("hash_password");
        assert!(
            check_password(&hash, "s3cret-password"),
            "check_password rejected the correct password"
        );
        assert!(
            !check_password(&hash, "wrong-password"),
            "check_password accepted a wrong password"
        );
        assert!(
            !check_password("not-a-hash", "s3cret-password"),
            "check_password accepted a malformed hash"
        );
    }
}
