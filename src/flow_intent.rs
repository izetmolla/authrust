//! Signed, short-lived markers that survive the OAuth round-trip.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::authorization::Authorization;
use crate::cookies::{CookieJar, expire_cookie, read_cookie, set_cookie};
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::response::ResponseWriter;

type HmacSha256 = Hmac<Sha256>;

/// Marks an OAuth request that links extended provider scopes.
pub const FLOW_INTENT_CONNECT: &str = "connect";

fn flow_intent_hash(intent: &str, secret: &str) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(intent.as_bytes());
    mac.update(secret.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn signed_flow_intent_value(intent: &str, secret: &str) -> String {
    format!("{intent}|{}", flow_intent_hash(intent, secret))
}

fn verify_flow_intent_cookie(cookie_value: &str, intent: &str, secret: &str) -> bool {
    let Some((value, signature)) = cookie_value.split_once('|') else {
        return false;
    };
    if value != intent {
        return false;
    }
    let expected = flow_intent_hash(intent, secret);
    bool::from(signature.as_bytes().ct_eq(expected.as_bytes()))
}

impl Authorization {
    /// Stores a signed, short-lived intent marker for the OAuth round-trip.
    pub fn set_flow_intent_cookie(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        intent: &str,
    ) -> Result<()> {
        if intent.is_empty() {
            return Err(Error::msg("flow intent is required"));
        }
        if self.jwt_secret().is_empty() {
            return Err(Error::config("JWTSecret is required to sign flow intent"));
        }
        let (_, secure) = self.origin(r)?;
        set_cookie(
            w,
            &self.jar(secure).flow_intent(),
            &signed_flow_intent_value(intent, self.jwt_secret()),
        );
        Ok(())
    }

    /// Reads and clears the intent cookie, reporting whether it carried the
    /// expected, correctly signed intent.
    pub fn consume_flow_intent(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        jar: &CookieJar,
        intent: &str,
    ) -> bool {
        if intent.is_empty() || self.jwt_secret().is_empty() {
            return false;
        }
        let cookie = read_cookie(r, &jar.flow_intent().name);
        expire_cookie(w, &jar.flow_intent());
        if cookie.is_empty() {
            return false;
        }
        verify_flow_intent_cookie(&cookie, intent, self.jwt_secret())
    }
}
