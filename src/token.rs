//! JWT claims, header parsing and token issuance.

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::authorization::Authorization;
use crate::authorize::{AuthorizeOptions, AuthorizeOptionsFunc, new_authorize_options};
use crate::constants::{DEFAULT_ACCESS_TOKEN_DURATION, DEFAULT_REFRESH_TOKEN_DURATION};
use crate::cookies::read_cookie;
use crate::csrf::verify_csrf;
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::session::Session;
use crate::types::{JsonbAny, JsonbArray};
use crate::utils::{go_duration_string, parse_custom_duration, resolve_signing_method};

/// The claims embedded in access tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String,
    #[serde(default)]
    pub content: JsonbAny,
    #[serde(default)]
    pub roles: JsonbArray,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
}

/// The claims embedded in refresh tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub session_id: String,
    pub user_id: String,
    /// The lifetime of the *access* token this refresh token can mint, not the
    /// refresh token's own lifetime.
    #[serde(
        rename = "tokenlife",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub access_token_lifetime: String,
    #[serde(
        rename = "signing_method",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub signing_method_hmac: String,
    #[serde(default, skip_serializing_if = "JsonbAny::is_empty")]
    pub content: JsonbAny,
    #[serde(default, skip_serializing_if = "JsonbArray::is_empty")]
    pub roles: JsonbArray,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
}

/// Groups the access/refresh pair returned to clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl Authorization {
    // --- Header & token parsing -------------------------------------------

    /// Strips the `Bearer ` / `Token ` scheme from an `Authorization` header
    /// value. Returns the value as-is when no scheme is set, and an error when
    /// the header is empty.
    pub fn get_token_from_header(&self, auth_header: &str) -> Result<String> {
        if auth_header.is_empty() {
            return Err(Error::msg("authorization header is required"));
        }
        for scheme in ["Bearer ", "Token "] {
            if auth_header.len() > scheme.len()
                && auth_header[..scheme.len()].eq_ignore_ascii_case(scheme)
            {
                return Ok(auth_header[scheme.len()..].to_string());
            }
        }
        Ok(auth_header.to_string())
    }

    /// Parses and validates a refresh token, returning its claims.
    pub fn extract_token(&self, token_string: &str) -> Result<RefreshTokenClaims> {
        let data =
            decode::<RefreshTokenClaims>(token_string, &self.decoding_key(), &self.validation())?;
        Ok(data.claims)
    }

    /// The HMAC key used to verify tokens.
    pub(crate) fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.jwt_secret().as_bytes())
    }

    /// The HMAC key used to sign tokens.
    pub(crate) fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.jwt_secret().as_bytes())
    }

    /// Validation rules matching Go's key function: any HMAC algorithm is
    /// accepted, and audience/issuer are not checked.
    pub(crate) fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.algorithms = vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];
        validation.validate_aud = false;
        validation
    }

    // --- Token issuance ----------------------------------------------------

    /// Issues a new access token from a previously-validated refresh-token claim
    /// set and the matching session row.
    ///
    /// Extra functional options can be passed to override the embedded content.
    pub fn refresh_access_token(
        &self,
        refresh_token_claims: &RefreshTokenClaims,
        session_data: &Session,
        opts: impl IntoIterator<Item = AuthorizeOptionsFunc>,
    ) -> Result<String> {
        let options = new_authorize_options(opts);

        let access_token_duration =
            parse_custom_duration(self.access_token_duration(), DEFAULT_ACCESS_TOKEN_DURATION)?;

        let now = Utc::now();
        let claims = Claims {
            user_id: refresh_token_claims.user_id.clone(),
            content: options.content,
            roles: session_data.user.roles.clone(),
            exp: Some((now + access_token_duration).timestamp()),
            iat: Some(now.timestamp()),
        };
        Ok(encode(&self.header(), &claims, &self.encoding_key())?)
    }

    /// Signs an access and a refresh token in one shot. The current time is
    /// read once and reused so the lifetimes line up exactly.
    pub fn sign_token_pair(
        &self,
        o: &AuthorizeOptions,
        session_id: &str,
    ) -> Result<(String, String)> {
        if session_id.is_empty() {
            return Err(Error::msg("session ID is required"));
        }

        let now = Utc::now();

        let access_token_duration =
            parse_custom_duration(self.access_token_duration(), DEFAULT_ACCESS_TOKEN_DURATION)?;
        let access_claims = Claims {
            user_id: o.user_id.clone(),
            content: o.content.clone(),
            roles: o.roles.clone(),
            exp: Some((now + access_token_duration).timestamp()),
            iat: Some(now.timestamp()),
        };
        let access_token = encode(&self.header(), &access_claims, &self.encoding_key())
            .map_err(|err| Error::msg(format!("sign access token: {err}")))?;

        let refresh_token_duration = parse_custom_duration(
            self.refresh_token_duration(),
            DEFAULT_REFRESH_TOKEN_DURATION,
        )?;
        let refresh_claims = RefreshTokenClaims {
            session_id: session_id.to_string(),
            user_id: o.user_id.clone(),
            access_token_lifetime: go_duration_string(access_token_duration),
            signing_method_hmac: self.signing_method().to_string(),
            content: o.content.clone(),
            roles: o.roles.clone(),
            exp: Some((now + refresh_token_duration).timestamp()),
            iat: Some(now.timestamp()),
        };
        let refresh_token = encode(&self.header(), &refresh_claims, &self.encoding_key())
            .map_err(|err| Error::msg(format!("sign refresh token: {err}")))?;

        Ok((access_token, refresh_token))
    }

    fn header(&self) -> Header {
        Header::new(resolve_signing_method(self.signing_method()))
    }

    /// Reports whether the response should be tokens (JSON) rather than a
    /// session cookie plus redirect.
    pub fn wants_tokens(&self, r: &RequestContext<'_>) -> bool {
        r.header("x-auth-flow").eq_ignore_ascii_case("token") || r.query_get("flow") == "token"
    }

    /// Validates the signed double-submit token for unsafe actions.
    pub fn check_csrf(&self, r: &RequestContext<'_>, secure: bool) -> bool {
        let jar = self.jar(secure);
        let cookie_value = read_cookie(r, &jar.csrf_token().name);
        let body = r.form_value("csrfToken");
        let (_, ok) = verify_csrf(&cookie_value, body, self.jwt_secret());
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Config;
    use crate::roles::format_roles;
    use serde_json::json;
    use std::time::Duration;

    fn test_authorization() -> Authorization {
        Authorization::from_config_unchecked(Config {
            jwt_secret: "test-secret".to_string(),
            access_token_duration: "5m".to_string(),
            refresh_token_duration: "7d".to_string(),
            ..Config::default()
        })
    }

    #[test]
    fn get_token_from_header_strips_schemes() {
        let a = test_authorization();
        let cases: &[(&str, &str)] = &[
            ("Bearer abc.def.ghi", "abc.def.ghi"),
            ("bearer abc.def.ghi", "abc.def.ghi"),
            ("Token abc.def.ghi", "abc.def.ghi"),
            ("abc.def.ghi", "abc.def.ghi"),
        ];
        for (header, want) in cases {
            assert_eq!(
                a.get_token_from_header(header).unwrap(),
                *want,
                "{header:?}"
            );
        }
        assert!(a.get_token_from_header("").is_err(), "empty header errors");
    }

    #[test]
    fn sign_token_pair_round_trip() {
        let a = test_authorization();
        let options = new_authorize_options([
            a.with_user_id("user-1"),
            a.with_user_roles(JsonbArray(vec![json!("admin:rw"), json!("hr:r")])),
        ]);

        let (access_token, refresh_token) = a
            .sign_token_pair(&options, "session-1")
            .expect("sign_token_pair");

        let refresh_claims = a.extract_token(&refresh_token).expect("extract_token");
        assert_eq!(refresh_claims.session_id, "session-1");
        assert_eq!(refresh_claims.user_id, "user-1");

        // "tokenlife" must describe the ACCESS token lifetime (5m), not the
        // refresh token duration (7d).
        assert_eq!(
            refresh_claims.access_token_lifetime,
            go_duration_string(Duration::from_secs(300))
        );

        let access = decode::<Claims>(&access_token, &a.decoding_key(), &a.validation())
            .expect("parse access token");
        assert_eq!(access.claims.user_id, "user-1");
        assert_eq!(
            format_roles(&access.claims.roles),
            vec!["admin:rw".to_string(), "hr:r".to_string()]
        );

        // The access token must expire well before the refresh token.
        assert!(
            access.claims.exp < refresh_claims.exp,
            "access token expiry {:?} is not before refresh token expiry {:?}",
            access.claims.exp,
            refresh_claims.exp
        );
    }
}
