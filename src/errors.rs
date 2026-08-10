//! Error type for the crate.
//!
//! Failures are represented as variants of a single [`Error`] enum. Match on
//! the variant (or use helpers on [`Error`]) instead of comparing sentinel
//! values.

use std::fmt;

/// The crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// A boxed, thread-safe error, used where a foreign error is passed through.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Every failure mode of the authorization package.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `Authorization` value was not constructed through [`crate::Authorization::new`].
    #[error("authorization: not initialized")]
    NotInitialized,

    /// No validated JWT was found on the request extensions.
    #[error("authorization: missing jwt token in context")]
    MissingJwtContext,

    /// The token carried claims that could not be interpreted.
    #[error("authorization: invalid claims")]
    InvalidClaims,

    /// The `roles` claim was missing or had an unsupported shape.
    #[error("authorization: invalid roles")]
    InvalidRoles,

    /// No refresh token was supplied on the request.
    #[error("authorization: refresh token is required")]
    MissingRefreshToken,

    /// The refresh token failed validation.
    #[error("authorization: invalid refresh token")]
    InvalidRefreshToken,

    /// No live session row matched the identifier.
    #[error("authorization: session not found")]
    SessionNotFound,

    /// The session row exists but is past its expiry.
    #[error("authorization: session expired")]
    SessionExpired,

    /// A required configuration value was missing or invalid.
    #[error("{0}")]
    Config(String),

    /// The database rejected a query, or returned no rows where one was required.
    #[error(transparent)]
    Database(#[from] sqlx::Error),

    /// The Redis session cache failed.
    #[error(transparent)]
    Redis(#[from] redis::RedisError),

    /// A JWT could not be signed or verified.
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// A JSON payload could not be encoded or decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// An outbound HTTP call to an OAuth provider failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Any other failure, carrying a human-readable message.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Builds an [`Error::Other`] from anything printable, the analogue of
    /// `errors.New` / `fmt.Errorf` at the Go call sites.
    pub fn msg(message: impl fmt::Display) -> Self {
        Error::Other(message.to_string())
    }

    /// Builds an [`Error::Config`] from anything printable.
    pub fn config(message: impl fmt::Display) -> Self {
        Error::Config(message.to_string())
    }

    /// Reports whether this error means "no live session", covering both the
    /// sentinel variants and the database's row-not-found error. The Go code
    /// spells this out as `errors.Is(err, gorm.ErrRecordNotFound) || ...` at
    /// every call site.
    pub fn is_session_missing(&self) -> bool {
        matches!(
            self,
            Error::SessionNotFound | Error::Database(sqlx::Error::RowNotFound)
        )
    }

    /// Reports whether this error is the session-expired sentinel.
    pub fn is_session_expired(&self) -> bool {
        matches!(self, Error::SessionExpired)
    }
}
