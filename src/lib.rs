//! Framework-agnostic authentication and authorization for Rust.
//!
//! Built on [`http`] and [`tower`]: OAuth 2.0 / OpenID Connect, credentials,
//! LDAP, JWT access/refresh tokens, PostgreSQL sessions (optional Redis cache),
//! cookies, CSRF protection, and role-based access control.
//!
//! # Getting started
//!
//! 1. Add the crate (the `axum` feature is on by default):
//!
//! ```toml
//! [dependencies]
//! authrust = "0.1"
//! ```
//!
//! 2. Build an [`Authorization`] from a [`Config`], then mount the handlers and
//!    layers on your router:
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
//! let app = axum::Router::new()
//!     .merge(auth.handler())
//!     .layer(auth.use_api_authorization([]));
//! # let _ = app;
//! # Ok(())
//! # }
//! ```
//!
//! # What you get
//!
//! | Area | Details |
//! |------|---------|
//! | **Providers** | Google, Azure AD / Entra ID, credentials, LDAP — see [`providers`] |
//! | **Tokens** | HS256 / HS384 / HS512 access + refresh pairs |
//! | **Sessions** | PostgreSQL via `sqlx`, optional Redis cache |
//! | **API protection** | [`Authorization::use_api_authorization`] — Bearer JWT |
//! | **Web protection** | [`Authorization::use_web_authorization`] — session cookie + redirect |
//! | **Refresh** | [`Authorization::handle_refresh_token`] — opt-in refresh endpoint |
//! | **RBAC** | `name:perms` grants (`admin:rw`, `hr:r`, …) |
//!
//! # HTTP endpoints
//!
//! With the `axum` feature, [`Authorization::handler`] mounts routes under
//! [`DEFAULT_BASE_PATH`] (`/api/authorization`):
//!
//! - `GET {base}/providers` — list configured providers
//! - `{base}/provider/{provider}` — start sign-in
//! - `{base}/provider/{provider}/callback` — OAuth/OIDC callback
//!
//! Without axum, register the individual handlers yourself or use
//! [`Authorization::route`] as a catch-all dispatcher.
//!
//! # Frameworks
//!
//! Middlewares are `tower` layers and handlers are plain `http` services, so the
//! crate works with axum, hyper, tonic, and other `tower` stacks. actix-web needs
//! a thin adapter (see the repository examples).
//!
//! # Crate features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `axum` | yes | Enables [`Authorization::handler`] returning an `axum::Router` |
//!
//! # Re-exports
//!
//! Common types are re-exported at the crate root so call sites stay short
//! (`authrust::Authorization`, `authrust::Config`, …).

#![cfg_attr(docsrs, feature(doc_cfg))]

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

// Flat re-exports for the public API surface.

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
