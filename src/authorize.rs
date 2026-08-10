//! Session creation and token issuance.

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
