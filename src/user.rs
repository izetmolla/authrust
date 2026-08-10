//! User records and the authenticated principal of a request.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};
use sqlx::Row;

use crate::authorization::Authorization;
use crate::db::{bind_id, quote_ident, safe_sql};
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::roles::format_roles;
use crate::types::{JsonbAny, JsonbArray};
use crate::utils::string_claim;

/// A user of the application, as far as this crate is concerned: an id, a set
/// of role grants and arbitrary extra content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub roles: JsonbArray,
    #[serde(default)]
    pub content: JsonbAny,
    /// Extra fields merged into the serialized user; not persisted by this
    /// crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<JsonbAny>,
}

/// The information common amongst most OAuth and OAuth2 providers. All the raw
/// data from the provider is kept in `raw_data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthUser {
    pub id: String,
    #[serde(default)]
    pub raw_data: JsonMap<String, Value>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub nick_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub access_token_secret: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub id_token: String,
    #[serde(default)]
    pub image: String,
}

/// The authenticated principal, extracted from either a JWT (API requests) or a
/// session cookie (WEB requests).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthData {
    pub session_id: String,
    pub user_id: String,
    pub roles: Vec<String>,
}

impl Authorization {
    /// Loads the current role grants of a user straight from the database.
    pub async fn get_user_roles_from_db(&self, user_id: &str) -> Result<JsonbArray> {
        let db = self.db()?;
        if user_id.is_empty() {
            return Err(Error::msg("user ID cannot be empty"));
        }
        let sql = safe_sql(format!(
            "SELECT roles FROM {} WHERE id = $1 LIMIT 1",
            quote_ident(self.user_table_name())
        ));
        let query = sqlx::query(&sql);
        let row = bind_id!(query, user_id).fetch_one(db).await?;
        let roles: Option<Value> = row.try_get("roles")?;
        JsonbArray::scan(roles.as_ref())
    }

    /// Returns the authenticated principal for the current request.
    ///
    /// Pass `from_api = true` to read it out of the JWT instead of the session
    /// cookie.
    pub async fn user(&self, r: &RequestContext<'_>, from_api: bool) -> Result<AuthData> {
        if from_api {
            self.get_auth_data_api(r)
        } else {
            self.get_auth_data_web(r).await
        }
    }

    /// Extracts the authenticated principal from a JWT-protected request.
    pub fn get_auth_data_api(&self, r: &RequestContext<'_>) -> Result<AuthData> {
        let claims = self.get_claims(r)?;
        Ok(AuthData {
            session_id: string_claim(claims, "session_id"),
            user_id: string_claim(claims, "user_id"),
            roles: self.get_roles(r).unwrap_or_default(),
        })
    }

    /// Extracts the authenticated principal from a cookie-protected request by
    /// loading the matching session row.
    pub async fn get_auth_data_web(&self, r: &RequestContext<'_>) -> Result<AuthData> {
        let session = self.get_session(&self.get_session_id(r)).await?;
        Ok(AuthData {
            session_id: session.id,
            user_id: session.user_id,
            roles: format_roles(&session.user.roles),
        })
    }
}
