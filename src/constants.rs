//! Token, session and cookie defaults, plus the header identifiers used by the
//! middlewares to coordinate optional flows.

use std::time::Duration;

/// Header that opts a request into the refresh-token middleware.
pub const REFRESH_TOKEN_HANDLER_IDENTIFIER: &str = "cft";

/// Header that opts a request into the re-authorization flow.
pub const REAUTHORIZE_HANDLER_IDENTIFIER: &str = "cra";

/// Default table holding user rows; needs at least `id` and `roles` columns.
pub const DEFAULT_USER_TABLE_NAME: &str = "users";

/// Default table holding session rows.
pub const DEFAULT_SESSION_TABLE_NAME: &str = "sessions";

/// Default access-token lifetime.
pub const DEFAULT_ACCESS_TOKEN_DURATION: &str = "60s";

/// Default refresh-token lifetime.
pub const DEFAULT_REFRESH_TOKEN_DURATION: &str = "1y";

/// Default JWT signing algorithm.
pub const DEFAULT_SIGNING_METHOD_HMAC: &str = "HS256";

/// Default time-to-live for cached sessions in Redis.
pub const DEFAULT_REDIS_TTL: Duration = Duration::from_secs(30 * 60);

/// Default key prefix for cached sessions in Redis.
pub const DEFAULT_REDIS_PREFIX: &str = "AUTHSESSIONS";

/// Default name of the WEB session cookie.
pub const DEFAULT_COOKIE_SESSION_NAME: &str = "cnf.id";

/// Default target of the WEB middleware's sign-in redirect.
pub const DEFAULT_SIGN_IN_REDIRECT_URL: &str = "/sign-in";

/// URL prefix under which [`crate::Authorization::handler`] mounts the
/// authorization endpoints.
pub const DEFAULT_BASE_PATH: &str = "/api/authorization";
