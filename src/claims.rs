//! Access to the validated JWT that the API middleware attaches to a request.
//!
//! Go stores the token under a private context key; Rust stores it in the
//! request extensions, which serve the same purpose.

use http::Extensions;
use jsonwebtoken::Header;
use serde_json::{Map as JsonMap, Value};

use crate::authorization::Authorization;
use crate::errors::{Error, Result};
use crate::http::RequestContext;

/// A validated JWT: its header and its decoded claim set.
#[derive(Debug, Clone)]
pub struct JwtToken {
    pub header: Header,
    pub claims: JsonMap<String, Value>,
}

/// Stores a validated token on the request extensions.
pub fn with_jwt(extensions: &mut Extensions, token: JwtToken) {
    extensions.insert(token);
}

/// Returns the validated JWT stored by the API middleware, or `None` when the
/// request was not authenticated.
pub fn jwt_from_context(extensions: &Extensions) -> Option<&JwtToken> {
    extensions.get::<JwtToken>()
}

impl Authorization {
    /// Returns the claims set by the JWT middleware. It errors out if no token
    /// is present on the request.
    pub fn get_claims<'a>(&self, r: &'a RequestContext<'a>) -> Result<&'a JsonMap<String, Value>> {
        let token = jwt_from_context(r.extensions()).ok_or(Error::MissingJwtContext)?;
        Ok(&token.claims)
    }
}
