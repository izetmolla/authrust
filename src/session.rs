//! Session rows, their Redis cache and the WEB session cookie.

use std::time::Duration;

use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::authorization::Authorization;
use crate::authorize::AuthorizeOptions;
use crate::constants::DEFAULT_REFRESH_TOKEN_DURATION;
use crate::cookies::{CookieOption, read_cookie, set_cookie};
use crate::db::{bind_id, quote_ident, safe_sql};
use crate::errors::{Error, Result};
use crate::http::{RequestContext, is_secure_request};
use crate::response::ResponseWriter;
use crate::session_check::session_usable;
use crate::types::{Account, JsonbAny, JsonbArray};
use crate::user::User;
use crate::utils::{
    build_redis_key, deserialize_session_data, parse_custom_duration, serialize_session_data,
    validate_session_data,
};

/// The trimmed session representation held in the Redis cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionData {
    pub id: String,
    pub user_id: String,
    #[serde(default)]
    pub roles: JsonbArray,
}

/// How a session was established.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    #[default]
    SignIn,
    OAuth,
}

impl SessionType {
    /// The value stored in the session row's `type` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionType::SignIn => "sign_in",
            SessionType::OAuth => "oauth",
        }
    }
}

/// A persisted session and, when loaded, its user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    /// Loaded alongside the session; not a column of the sessions table.
    #[serde(default)]
    pub user: User,
    #[serde(rename = "type", default)]
    pub type_: SessionType,

    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub method: String,

    #[serde(default)]
    pub account: JsonbAny,

    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_deleted: bool,

    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Session {
    /// Reads a session row selected by [`SESSION_COLUMNS`].
    pub(crate) fn from_row(row: &PgRow) -> Result<Self> {
        let account: Option<Value> = row.try_get("account")?;
        Ok(Session {
            id: row.try_get::<Option<String>, _>("id")?.unwrap_or_default(),
            user_id: row
                .try_get::<Option<String>, _>("user_id")?
                .unwrap_or_default(),
            user: User::default(),
            type_: match row
                .try_get::<Option<String>, _>("type")?
                .unwrap_or_default()
                .as_str()
            {
                "oauth" => SessionType::OAuth,
                _ => SessionType::SignIn,
            },
            ip_address: row
                .try_get::<Option<String>, _>("ip_address")?
                .unwrap_or_default(),
            user_agent: row
                .try_get::<Option<String>, _>("user_agent")?
                .unwrap_or_default(),
            method: row
                .try_get::<Option<String>, _>("method")?
                .unwrap_or_default(),
            account: JsonbAny::scan(account.as_ref())?,
            expires_at: row.try_get("expires_at")?,
            is_deleted: row
                .try_get::<Option<bool>, _>("is_deleted")?
                .unwrap_or(false),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

/// The projection every session query uses. `id` columns are cast to text so
/// the same code works against `uuid` and text primary keys.
pub(crate) const SESSION_COLUMNS: &str = r#"id::text AS id, user_id::text AS user_id, "type"::text AS "type", ip_address, user_agent, method, account, expires_at, is_deleted, created_at, updated_at, deleted_at"#;

impl Authorization {
    // --- Session & user lookup --------------------------------------------

    /// Loads a session (and its user) by id, using the Redis cache when
    /// available.
    pub async fn get_session(&self, session_id: &str) -> Result<Session> {
        self.get_session_from_db(session_id).await
    }

    /// Loads a session from Redis when configured, falling back to the database.
    pub async fn get_session_from_db(&self, session_id: &str) -> Result<Session> {
        let db = self.db()?;
        if session_id.is_empty() {
            return Err(Error::msg("session ID cannot be empty"));
        }

        if self.redis().is_some() {
            if let Ok(cached) = self.get_session_from_redis(session_id).await {
                self.ensure_session_active(session_id).await?;
                let mut roles = cached.roles;
                if let Ok(fresh) = self.get_user_roles_from_db(&cached.user_id).await {
                    if !fresh.is_empty() {
                        roles = fresh;
                        let _ = self
                            .set_session_to_redis(&SessionData {
                                id: cached.id.clone(),
                                user_id: cached.user_id.clone(),
                                roles: roles.clone(),
                            })
                            .await;
                    }
                }
                return Ok(Session {
                    id: cached.id,
                    user_id: cached.user_id.clone(),
                    user: User {
                        id: cached.user_id,
                        roles,
                        ..User::default()
                    },
                    ..Session::default()
                });
            }
        }

        let sql = safe_sql(format!(
            "SELECT {SESSION_COLUMNS} FROM {} WHERE id = $1 AND is_deleted = false LIMIT 1",
            quote_ident(self.sessions_table())
        ));
        let query = sqlx::query(&sql);
        let row = bind_id!(query, session_id).fetch_one(db).await?;
        let mut session = Session::from_row(&row)?;

        // The Redis path validates liveness via `ensure_session_active`; the
        // database fallback must apply the same rules or logged-out/expired
        // sessions keep authenticating.
        session_usable(Some(&session))?;

        session.user = self.load_session_user(&session.user_id).await?;

        if self.redis().is_some() {
            let _ = self
                .set_session_to_redis(&SessionData {
                    id: session.id.clone(),
                    user_id: session.user_id.clone(),
                    roles: session.user.roles.clone(),
                })
                .await;
        }
        Ok(session)
    }

    async fn load_session_user(&self, user_id: &str) -> Result<User> {
        let db = self.db()?;
        let sql = safe_sql(format!(
            "SELECT id::text AS id, roles FROM {} WHERE id = $1 LIMIT 1",
            quote_ident(self.user_table_name())
        ));
        let query = sqlx::query(&sql);
        let row = bind_id!(query, user_id).fetch_one(db).await?;
        let roles: Option<Value> = row.try_get("roles")?;
        Ok(User {
            id: row.try_get::<Option<String>, _>("id")?.unwrap_or_default(),
            roles: JsonbArray::scan(roles.as_ref())?,
            ..User::default()
        })
    }

    /// Retrieves session data from the Redis cache.
    pub async fn get_session_from_redis(&self, session_id: &str) -> Result<SessionData> {
        if session_id.is_empty() {
            return Err(Error::msg("session ID cannot be empty"));
        }
        let mut conn = self.redis_connection().await?;
        let redis_key = build_redis_key(self.redis_prefix(), session_id);
        let data: Option<String> = conn.get(&redis_key).await?;
        match data {
            Some(data) => deserialize_session_data(&data),
            None => Err(Error::SessionNotFound),
        }
    }

    /// Stores session data in the Redis cache.
    pub async fn set_session_to_redis(&self, session: &SessionData) -> Result<()> {
        validate_session_data(session)?;
        let mut conn = self.redis_connection().await?;
        let redis_key = build_redis_key(self.redis_prefix(), &session.id);
        let data = serialize_session_data(session)?;
        let ttl = self.redis_ttl().as_secs().max(1);
        let _: () = conn.set_ex(&redis_key, data, ttl).await?;
        Ok(())
    }

    /// Persists a new session row and returns its id.
    pub async fn create_session(&self, o: &AuthorizeOptions) -> Result<String> {
        let db = self.db()?;

        let refresh_token_duration = parse_custom_duration(
            self.refresh_token_duration(),
            DEFAULT_REFRESH_TOKEN_DURATION,
        )
        .map_err(|err| Error::msg(format!("parse refresh token duration: {err}")))?;

        let now = Utc::now();
        let expires_at = now + refresh_token_duration;
        let session_id = Uuid::new_v4();
        let account = account_to_jsonb(o.account.as_ref()).map(|value| value.to_value());

        // `user_id` is nullable, but a typed NULL cannot be bound without
        // knowing the column type, so the column is omitted when unset.
        let table = quote_ident(self.sessions_table());
        let sql = safe_sql(if o.user_id.is_empty() {
            format!(
                "INSERT INTO {table} (id, ip_address, user_agent, method, account, expires_at, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) RETURNING id::text AS id"
            )
        } else {
            format!(
                "INSERT INTO {table} (id, user_id, ip_address, user_agent, method, account, expires_at, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) RETURNING id::text AS id"
            )
        });

        let query = sqlx::query(&sql).bind(session_id);
        let query = if o.user_id.is_empty() {
            query
        } else {
            bind_id!(query, &o.user_id)
        };
        let row = query
            .bind(&o.ip_address)
            .bind(&o.user_agent)
            .bind(&o.method)
            .bind(account)
            .bind(expires_at)
            .bind(now)
            .fetch_one(db)
            .await?;

        Ok(row
            .try_get::<Option<String>, _>("id")?
            .unwrap_or_else(|| session_id.to_string()))
    }

    /// Returns the session id carried by the request's session cookie, or `""`.
    pub fn get_session_id(&self, r: &RequestContext<'_>) -> String {
        read_cookie(r, self.cookie_session_name())
    }

    /// Writes the WEB session cookie used by
    /// [`Authorization::use_web_authorization`].
    pub fn set_session_id_cookie(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        session_id: &str,
    ) {
        if session_id.is_empty() {
            return;
        }
        let secure = is_secure_request(r);
        let max_age = parse_custom_duration(
            self.refresh_token_duration(),
            DEFAULT_REFRESH_TOKEN_DURATION,
        )
        .unwrap_or(Duration::from_secs(365 * 24 * 60 * 60));

        set_cookie(
            w,
            &CookieOption {
                name: self.cookie_session_name().to_string(),
                http_only: true,
                same_site: Some(cookie::SameSite::Lax),
                path: "/".to_string(),
                secure,
                max_age,
                domain: String::new(),
            },
            session_id,
        );
    }
}

/// Converts an account into the JSONB payload stored on the session row.
pub(crate) fn account_to_jsonb(account: Option<&Account>) -> Option<JsonbAny> {
    let account = account?;
    let value = serde_json::to_value(account).ok()?;
    match value {
        Value::Object(map) => Some(JsonbAny(map)),
        _ => None,
    }
}
