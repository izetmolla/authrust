//! Session creation and token issuance.
//!
//! Go's `WithContext` on authorize options is not mirrored: Rust uses async
//! `sqlx` queries instead of GORM's `WithContext`, so cancellation belongs on
//! the surrounding async task / `tokio` cancellation rather than a field on
//! [`AuthorizeOptions`].

use crate::authorization::Authorization;
use crate::errors::{Error, Result};
use crate::token::Tokens;
use crate::types::{Account, JsonbAny, JsonbArray};

/// Carries every input required to issue a new token pair. Build it via the
/// functional options ([`Authorization::with_user_id`], ...).
#[derive(Debug, Clone)]
pub struct AuthorizeOptions {
    pub(crate) user_id: String,
    pub(crate) account: Option<Account>,
    pub(crate) ip_address: String,
    pub(crate) user_agent: String,
    pub(crate) content: JsonbAny,
    pub(crate) roles: JsonbArray,
    pub(crate) method: String,
}

impl Default for AuthorizeOptions {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            account: None,
            ip_address: String::new(),
            user_agent: String::new(),
            content: JsonbAny::new(),
            roles: JsonbArray::new(),
            method: "credentials".to_string(),
        }
    }
}

impl AuthorizeOptions {
    /// The user the tokens are issued for.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// The role grants embedded in the tokens.
    pub fn roles(&self) -> &JsonbArray {
        &self.roles
    }

    /// The arbitrary content embedded in the tokens.
    pub fn content(&self) -> &JsonbAny {
        &self.content
    }
}

/// The functional-option type used with [`Authorization::authorize`],
/// [`Authorization::refresh_access_token`] and the low-level token generators.
///
/// The `Send` bound lets a set of options be held across an `.await`, which the
/// sign-in handlers rely on.
pub type AuthorizeOptionsFunc = Box<dyn FnOnce(&mut AuthorizeOptions) + Send>;

/// Applies the provided functional options on top of the defaults.
pub fn new_authorize_options(
    opts: impl IntoIterator<Item = AuthorizeOptionsFunc>,
) -> AuthorizeOptions {
    let mut o = AuthorizeOptions::default();
    for opt in opts {
        opt(&mut o);
    }
    o
}

impl Authorization {
    /// Creates a fresh session row and signs an access/refresh token pair for it.
    ///
    /// Returns the token pair and the new session id.
    pub async fn authorize(
        &self,
        opts: impl IntoIterator<Item = AuthorizeOptionsFunc>,
    ) -> Result<(Tokens, String)> {
        let mut options = new_authorize_options(opts);

        if !options.user_id.is_empty() {
            if let Ok(roles) = self.get_user_roles_from_db(&options.user_id).await {
                options.roles = roles;
            }
        }

        // Mirror goauth: reject payloads that do not serialize as valid JSON.
        if !is_valid_json_payload(&options.content.to_string()) {
            return Err(Error::msg("invalid content JSON payload"));
        }
        if !is_valid_json_payload(&options.roles.to_string()) {
            return Err(Error::msg("invalid roles JSON payload"));
        }

        let session_id = self
            .create_session(&options)
            .await
            .map_err(|err| Error::msg(format!("create session: {err}")))?;

        let (access_token, refresh_token) = self.sign_token_pair(&options, &session_id)?;

        Ok((
            Tokens {
                access_token,
                refresh_token,
            },
            session_id,
        ))
    }
}

/// Reports whether `raw` is valid JSON (same check as goauth's `json.Valid`).
fn is_valid_json_payload(raw: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(raw).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Config;

    fn test_auth() -> Authorization {
        Authorization::from_config_unchecked(Config {
            jwt_secret: "test-secret".into(),
            ..Config::default()
        })
    }

    #[test]
    fn valid_json_payloads_pass() {
        assert!(is_valid_json_payload("{}"));
        assert!(is_valid_json_payload("[]"));
        assert!(is_valid_json_payload(r#"{"a":1}"#));
        assert!(!is_valid_json_payload("{"));
        assert!(!is_valid_json_payload("not-json"));
    }

    #[test]
    fn with_content_sets_authorize_options() {
        let auth = test_auth();
        let mut content = JsonbAny::new();
        content.insert("plan".into(), serde_json::json!("pro"));
        let opts = new_authorize_options([auth.with_content(content.clone())]);
        assert_eq!(opts.content, content);
    }
}
