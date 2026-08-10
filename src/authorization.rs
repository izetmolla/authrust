//! Configuration and the [`Authorization`] handle every other module hangs off.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tokio::sync::OnceCell;

use crate::constants::*;
use crate::cookies::CookieOptions;
use crate::errors::{Error, Result};
use crate::provider::Provider;
use crate::types::{Account, Profile};
use crate::user::User;

/// Maps a raw provider profile onto a user in the application's own database.
///
/// Returns the resolved user and whether it was newly created. Required for
/// OAuth sign-in.
pub type ResolveUserFn =
    Arc<dyn Fn(Profile) -> BoxFuture<'static, Result<(Option<User>, bool)>> + Send + Sync>;

/// Persists extended OAuth scopes after a connect flow, when `resource_id` was
/// supplied on the authorization request.
pub type OnProviderConnectFn =
    Arc<dyn Fn(String, Account, User, String) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Mutates a [`Config`] in place, the analogue of Go's `ConfigFunc`.
pub type ConfigFunc = Box<dyn FnOnce(&mut Config) + Send>;

/// Everything needed to construct an [`Authorization`].
#[derive(Clone)]
pub struct Config {
    /// HMAC signing secret. Required.
    pub jwt_secret: String,
    /// External origin, e.g. `https://app.example.com`. Falls back to request
    /// headers when empty.
    pub auth_url: String,
    /// `HS256` (default), `HS384` or `HS512`.
    pub signing_method: String,
    /// Access-token lifetime in this crate's duration format (`60s`, `15m`, ...).
    pub access_token_duration: String,
    /// Refresh-token lifetime in this crate's duration format.
    pub refresh_token_duration: String,
    /// Target of the WEB middleware's redirect for unauthenticated requests.
    pub sign_in_redirect_url: String,

    /// PostgreSQL pool holding the users and sessions tables. Required.
    pub db: Option<PgPool>,
    /// Optional Redis client used to cache sessions.
    pub redis: Option<redis::Client>,
    /// Key prefix for cached sessions.
    pub redis_prefix: String,
    /// Time-to-live for cached sessions.
    pub redis_ttl: Duration,

    /// Table holding user rows; needs at least `id` and `roles` columns.
    pub user_table_name: String,
    /// Table holding session rows.
    pub session_table_name: String,

    /// Name of the WEB session cookie.
    pub cookie_session_name: String,
    /// Per-cookie overrides.
    pub cookies: CookieOptions,

    /// The ordered list of enabled providers.
    pub providers: Vec<Arc<dyn Provider>>,

    /// Maps a provider profile onto an application user.
    pub resolve_user: Option<ResolveUserFn>,
    /// Runs when a provider-connect flow completes.
    pub on_provider_connect: Option<OnProviderConnectFn>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(),
            auth_url: "localhost".to_string(),
            signing_method: DEFAULT_SIGNING_METHOD_HMAC.to_string(),
            access_token_duration: DEFAULT_ACCESS_TOKEN_DURATION.to_string(),
            refresh_token_duration: DEFAULT_REFRESH_TOKEN_DURATION.to_string(),
            sign_in_redirect_url: DEFAULT_SIGN_IN_REDIRECT_URL.to_string(),
            db: None,
            redis: None,
            redis_prefix: DEFAULT_REDIS_PREFIX.to_string(),
            redis_ttl: DEFAULT_REDIS_TTL,
            user_table_name: DEFAULT_USER_TABLE_NAME.to_string(),
            session_table_name: DEFAULT_SESSION_TABLE_NAME.to_string(),
            cookie_session_name: DEFAULT_COOKIE_SESSION_NAME.to_string(),
            cookies: CookieOptions::default(),
            providers: Vec::new(),
            resolve_user: None,
            on_provider_connect: None,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("auth_url", &self.auth_url)
            .field("signing_method", &self.signing_method)
            .field("access_token_duration", &self.access_token_duration)
            .field("refresh_token_duration", &self.refresh_token_duration)
            .field("sign_in_redirect_url", &self.sign_in_redirect_url)
            .field("db", &self.db.is_some())
            .field("redis", &self.redis.is_some())
            .field("redis_prefix", &self.redis_prefix)
            .field("redis_ttl", &self.redis_ttl)
            .field("user_table_name", &self.user_table_name)
            .field("session_table_name", &self.session_table_name)
            .field("cookie_session_name", &self.cookie_session_name)
            .field(
                "providers",
                &self.providers.iter().map(|p| p.id()).collect::<Vec<_>>(),
            )
            .field("resolve_user", &self.resolve_user.is_some())
            .field("on_provider_connect", &self.on_provider_connect.is_some())
            .finish()
    }
}

impl Config {
    /// Replaces empty fields with their defaults, so a partially filled config
    /// behaves like Go's `defaultConfig` merge.
    fn apply_defaults(&mut self) {
        let defaults = Config::default();
        for (field, default) in [
            (&mut self.auth_url, defaults.auth_url),
            (&mut self.signing_method, defaults.signing_method),
            (
                &mut self.access_token_duration,
                defaults.access_token_duration,
            ),
            (
                &mut self.refresh_token_duration,
                defaults.refresh_token_duration,
            ),
            (
                &mut self.sign_in_redirect_url,
                defaults.sign_in_redirect_url,
            ),
            (&mut self.redis_prefix, defaults.redis_prefix),
            (&mut self.user_table_name, defaults.user_table_name),
            (&mut self.session_table_name, defaults.session_table_name),
            (&mut self.cookie_session_name, defaults.cookie_session_name),
        ] {
            if field.is_empty() {
                *field = default;
            }
        }
        if self.redis_ttl.is_zero() {
            self.redis_ttl = defaults.redis_ttl;
        }
    }
}

#[derive(Clone)]
pub(crate) struct Inner {
    pub(crate) jwt_secret: String,
    pub(crate) auth_url: String,
    pub(crate) signing_method: String,
    pub(crate) access_token_duration: String,
    pub(crate) refresh_token_duration: String,
    pub(crate) sign_in_redirect_url: String,
    pub(crate) db: Option<PgPool>,
    pub(crate) redis: Option<redis::Client>,
    pub(crate) redis_manager: OnceCell<ConnectionManager>,
    pub(crate) redis_prefix: String,
    pub(crate) redis_ttl: Duration,
    pub(crate) user_table_name: String,
    pub(crate) session_table_name: String,
    pub(crate) cookie_session_name: String,
    pub(crate) providers: Vec<Arc<dyn Provider>>,
    pub(crate) cookies: CookieOptions,
    pub(crate) resolve_user: Option<ResolveUserFn>,
    pub(crate) on_provider_connect: Option<OnProviderConnectFn>,
}

/// The entry point of the crate: holds the configuration and exposes every
/// handler, middleware and helper.
///
/// Cloning is cheap; the value is a handle around shared state, mirroring the
/// `*Authorization` pointer the Go package passes around.
#[derive(Clone)]
pub struct Authorization {
    inner: Arc<Inner>,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("auth_url", &self.inner.auth_url)
            .field("signing_method", &self.inner.signing_method)
            .field("user_table_name", &self.inner.user_table_name)
            .field("session_table_name", &self.inner.session_table_name)
            .field(
                "providers",
                &self
                    .inner
                    .providers
                    .iter()
                    .map(|p| p.id())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Authorization {
    /// Validates the configuration and returns a ready-to-use handle.
    pub fn new(config: Config) -> Result<Self> {
        Self::new_with(config, [])
    }

    /// Applies the given options on top of `config` before validating it.
    pub fn new_with(
        mut config: Config,
        opts: impl IntoIterator<Item = ConfigFunc>,
    ) -> Result<Self> {
        for opt in opts {
            opt(&mut config);
        }
        config.apply_defaults();

        if config.jwt_secret.is_empty() {
            return Err(Error::config("jwt_secret is required"));
        }
        if config.db.is_none() {
            return Err(Error::config("db is required"));
        }
        Ok(Self::from_config_unchecked(config))
    }

    /// Builds a handle without validating the configuration. Used by tests that
    /// exercise pure helpers with no database.
    pub(crate) fn from_config_unchecked(mut config: Config) -> Self {
        config.apply_defaults();
        Self {
            inner: Arc::new(Inner {
                jwt_secret: config.jwt_secret,
                auth_url: config.auth_url,
                signing_method: config.signing_method,
                access_token_duration: config.access_token_duration,
                refresh_token_duration: config.refresh_token_duration,
                sign_in_redirect_url: config.sign_in_redirect_url,
                db: config.db,
                redis: config.redis,
                redis_manager: OnceCell::new(),
                redis_prefix: config.redis_prefix,
                redis_ttl: config.redis_ttl,
                user_table_name: config.user_table_name,
                session_table_name: config.session_table_name,
                cookie_session_name: config.cookie_session_name,
                providers: config.providers,
                cookies: config.cookies,
                resolve_user: config.resolve_user,
                on_provider_connect: config.on_provider_connect,
            }),
        }
    }

    // --- Accessors ---------------------------------------------------------

    /// The HMAC signing secret.
    pub fn jwt_secret(&self) -> &str {
        &self.inner.jwt_secret
    }

    /// The configured external origin.
    pub fn auth_url(&self) -> &str {
        &self.inner.auth_url
    }

    /// The configured JWT signing method name.
    pub fn signing_method(&self) -> &str {
        &self.inner.signing_method
    }

    /// The configured access-token lifetime.
    pub fn access_token_duration(&self) -> &str {
        &self.inner.access_token_duration
    }

    /// The configured refresh-token lifetime.
    pub fn refresh_token_duration(&self) -> &str {
        &self.inner.refresh_token_duration
    }

    /// The configured sign-in redirect target.
    pub fn sign_in_redirect_url(&self) -> &str {
        &self.inner.sign_in_redirect_url
    }

    /// The database pool, or [`Error::NotInitialized`] when none was configured.
    pub fn db(&self) -> Result<&PgPool> {
        self.inner
            .db
            .as_ref()
            .ok_or_else(|| Error::msg("db manager is not initialized"))
    }

    /// The configured Redis client, if any.
    pub fn redis(&self) -> Option<&redis::Client> {
        self.inner.redis.as_ref()
    }

    /// A pooled, auto-reconnecting Redis connection.
    pub(crate) async fn redis_connection(&self) -> Result<ConnectionManager> {
        let client = self
            .inner
            .redis
            .as_ref()
            .ok_or_else(|| Error::msg("redis is not configured"))?;
        let manager = self
            .inner
            .redis_manager
            .get_or_try_init(|| async { ConnectionManager::new(client.clone()).await })
            .await?;
        Ok(manager.clone())
    }

    /// The Redis key prefix.
    pub fn redis_prefix(&self) -> &str {
        &self.inner.redis_prefix
    }

    /// The Redis session time-to-live.
    pub fn redis_ttl(&self) -> Duration {
        self.inner.redis_ttl
    }

    /// The configured users table.
    pub fn user_table_name(&self) -> &str {
        &self.inner.user_table_name
    }

    /// The configured sessions table.
    pub fn sessions_table(&self) -> &str {
        if self.inner.session_table_name.is_empty() {
            DEFAULT_SESSION_TABLE_NAME
        } else {
            &self.inner.session_table_name
        }
    }

    /// The name of the WEB session cookie.
    pub fn cookie_session_name(&self) -> &str {
        &self.inner.cookie_session_name
    }

    /// The configured cookie overrides.
    pub fn cookies(&self) -> &CookieOptions {
        &self.inner.cookies
    }

    /// Every configured provider, in order.
    pub fn providers(&self) -> &[Arc<dyn Provider>] {
        &self.inner.providers
    }

    pub(crate) fn resolve_user_fn(&self) -> Option<&ResolveUserFn> {
        self.inner.resolve_user.as_ref()
    }

    pub(crate) fn on_provider_connect_fn(&self) -> Option<&OnProviderConnectFn> {
        self.inner.on_provider_connect.as_ref()
    }

    // --- Builders ----------------------------------------------------------

    /// Overrides the signing secret.
    pub fn with_jwt_secret(mut self, jwt_secret: &str) -> Self {
        if !jwt_secret.is_empty() {
            Arc::make_mut(&mut self.inner).jwt_secret = jwt_secret.to_string();
        }
        self
    }

    /// Overrides the external origin.
    pub fn with_auth_url(mut self, auth_url: &str) -> Self {
        if !auth_url.is_empty() {
            Arc::make_mut(&mut self.inner).auth_url = auth_url.to_string();
        }
        self
    }

    /// Overrides the database pool.
    pub fn with_db(mut self, db: PgPool) -> Self {
        Arc::make_mut(&mut self.inner).db = Some(db);
        self
    }

    /// Overrides the Redis client.
    pub fn with_redis(mut self, redis: redis::Client) -> Self {
        let inner = Arc::make_mut(&mut self.inner);
        inner.redis = Some(redis);
        inner.redis_manager = OnceCell::new();
        self
    }

    /// Overrides the Redis key prefix.
    pub fn with_redis_prefix(mut self, redis_prefix: &str) -> Self {
        if !redis_prefix.is_empty() {
            Arc::make_mut(&mut self.inner).redis_prefix = redis_prefix.to_string();
        }
        self
    }

    /// Overrides the Redis session time-to-live.
    pub fn with_redis_ttl(mut self, redis_ttl: Duration) -> Self {
        if !redis_ttl.is_zero() {
            Arc::make_mut(&mut self.inner).redis_ttl = redis_ttl;
        }
        self
    }

    /// Overrides the WEB session cookie name.
    pub fn with_cookie_session_name(mut self, cookie_session_name: &str) -> Self {
        if !cookie_session_name.is_empty() {
            Arc::make_mut(&mut self.inner).cookie_session_name = cookie_session_name.to_string();
        }
        self
    }

    /// Overrides the user-resolution callback.
    pub fn with_resolve_user(mut self, resolve_user: ResolveUserFn) -> Self {
        Arc::make_mut(&mut self.inner).resolve_user = Some(resolve_user);
        self
    }
}
