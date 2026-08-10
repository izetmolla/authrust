//! Framework-agnostic authentication and authorization, built on `http` and
//! `tower`.
//!
//! This is a Rust port of the Go `goauth` module and keeps its structure and
//! naming: an [`Authorization`] value is built from a [`Config`], exposes
//! middleware for API and web routes, and serves the provider endpoints under
//! [`DEFAULT_BASE_PATH`].
//!
//! # Overview
//!
//! - **Providers**: OAuth 2.0 / OpenID Connect, credentials, and LDAP. See
//!   [`providers`].
//! - **Tokens**: short-lived access tokens plus long-lived refresh tokens,
//!   signed with HMAC or RSA.
//! - **Sessions**: rows in PostgreSQL through `sqlx`, optionally cached in
//!   Redis.
//! - **Middleware**: [`ApiAuthorizationLayer`] validates bearer tokens,
//!   [`WebAuthorizationLayer`] validates the session cookie, and
//!   [`RefreshTokenLayer`] serves refresh requests.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use authrust::{Authorization, Config, providers::google};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;
//!
//! let auth = Authorization::new(Config {
//!     db: Some(pool),
//!     jwt_secret: "a-long-random-secret".into(),
//!     providers: vec![google::new("client-id", "client-secret")],
//!     resolve_user: Some(Arc::new(|profile| {
//!         Box::pin(async move {
//!             // Look the profile up in your own tables, creating it if needed,
//!             // and return the user plus whether it was just created.
//!             let _ = profile;
//!             Ok((Some(authrust::User::default()), false))
//!         })
//!     })),
//!     ..Config::default()
//! })?;
//!
//! # #[cfg(feature = "axum")]
//! let app = axum::Router::new().merge(auth.handler());
//! # Ok(())
//! # }
//! ```

pub mod action_auth;
pub mod authorization;
pub mod authorize;
pub mod callback_page;
pub mod checks;
pub mod claims;
pub mod connect_resource;
pub mod constants;
pub mod cookies;
pub mod csrf;
pub mod errors;
pub mod flow_intent;
pub mod http;
pub mod middleware;
pub mod oauth;
pub mod options;
pub mod password;
pub mod provider;
pub mod provider_utils;
pub mod providers;
pub mod redirect;
pub mod refresh;
pub mod response;
pub mod roles;
pub mod session;
pub mod session_check;
pub mod token;
pub mod types;
pub mod user;
pub mod utils;

#[macro_use]
mod db;

#[cfg(feature = "axum")]
mod axum_support;

// The Go module is a single flat package; these re-exports keep the same
// call sites available as `authrust::Item`.

pub use authorization::{Authorization, Config, ConfigFunc, OnProviderConnectFn, ResolveUserFn};
pub use authorize::{AuthorizeOptions, AuthorizeOptionsFunc, new_authorize_options};
pub use checks::{pkce_challenge, provider_uses_check, random_string};
pub use claims::{JwtToken, jwt_from_context, with_jwt};
pub use constants::{
    DEFAULT_ACCESS_TOKEN_DURATION, DEFAULT_BASE_PATH, DEFAULT_COOKIE_SESSION_NAME,
    DEFAULT_REDIS_PREFIX, DEFAULT_REDIS_TTL, DEFAULT_REFRESH_TOKEN_DURATION,
    DEFAULT_SESSION_TABLE_NAME, DEFAULT_SIGN_IN_REDIRECT_URL, DEFAULT_SIGNING_METHOD_HMAC,
    DEFAULT_USER_TABLE_NAME, REAUTHORIZE_HANDLER_IDENTIFIER, REFRESH_TOKEN_HANDLER_IDENTIFIER,
};
pub use cookies::{CookieJar, CookieOption, CookieOptions, cross_subdomain_cookies};
pub use csrf::{csrf_hash, verify_csrf};
pub use errors::{BoxError, Error, Result};
pub use http::{ClientAddr, ConnectionSecure, RequestContext, client_ip};
pub use middleware::{
    ApiAuthorization, ApiAuthorizationLayer, WebAuthorization, WebAuthorizationLayer,
};
pub use options::{AuthConfig, AuthConfigOptions, new_auth_config_options};
pub use password::{check_password, hash_password};
pub use provider::{
    Check, CredentialField, CredentialsAuthorizeFn, CredentialsProvider, CredentialsRequest,
    OAuthProvider, ProfileFn, Provider, ProviderType, PublicProvider, UrlValues,
};
pub use refresh::{RefreshToken, RefreshTokenLayer};
pub use response::{BoxedBody, BoxedResponse, Response, ResponseWriter};
pub use session::{Session, SessionData, SessionType};
pub use session_check::CheckSessionResult;
pub use token::{Claims, RefreshTokenClaims, Tokens};
pub use types::{Account, JsonbAny, JsonbArray, Profile, TokenSet};
pub use user::{AuthData, OAuthUser, User};
