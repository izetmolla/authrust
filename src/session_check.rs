//! Refresh-token driven session validation.

use chrono::Utc;

use crate::authorization::Authorization;
use crate::db::{bind_id, quote_ident, safe_sql};
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::response::ResponseWriter;
use crate::session::{SESSION_COLUMNS, Session};
use crate::token::Tokens;

/// Mirrors a successful sign-in payload without creating a session.
#[derive(Debug, Clone)]
pub struct CheckSessionResult {
    pub tokens: Tokens,
    pub session_id: String,
    pub user_id: String,
}

impl Authorization {
    /// Validates an existing refresh token and session, refreshes the access
    /// token with up-to-date roles, and sets the WEB session cookie.
    pub async fn check_session(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
    ) -> Result<CheckSessionResult> {
        let refresh_token = match self.get_token_from_header(r.header("authorization")) {
            Ok(token) => token,
            Err(_) => body_refresh_token(r),
        };
        if refresh_token.is_empty() {
            return Err(Error::MissingRefreshToken);
        }

        let claims = self
            .extract_token(&refresh_token)
            .map_err(|_| Error::InvalidRefreshToken)?;
        if claims.session_id.is_empty() {
            return Err(Error::InvalidRefreshToken);
        }

        self.ensure_session_active(&claims.session_id).await?;

        let session = self.get_session(&claims.session_id).await.map_err(|err| {
            if err.is_session_missing() {
                Error::SessionNotFound
            } else {
                err
            }
        })?;

        if !claims.user_id.is_empty() && claims.user_id != session.user_id {
            return Err(Error::InvalidRefreshToken);
        }

        let access_token = self.refresh_access_token(&claims, &session, [])?;

        self.set_session_id_cookie(w, r, &session.id);

        Ok(CheckSessionResult {
            tokens: Tokens {
                access_token,
                refresh_token,
            },
            session_id: session.id,
            user_id: session.user_id,
        })
    }

    /// Loads the session row and checks that it may still authenticate requests.
    pub async fn ensure_session_active(&self, session_id: &str) -> Result<()> {
        let db = self.db()?;
        let sql = safe_sql(format!(
            "SELECT {SESSION_COLUMNS} FROM {} WHERE id = $1 AND is_deleted = false LIMIT 1",
            quote_ident(self.sessions_table())
        ));
        let query = sqlx::query(&sql);
        let row = bind_id!(query, session_id)
            .fetch_one(db)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => Error::SessionNotFound,
                other => Error::Database(other),
            })?;
        let session = Session::from_row(&row)?;
        session_usable(Some(&session))
    }
}

/// Reports whether a loaded session row may still authenticate requests: it
/// must not be soft-deleted and must not be past its expiry.
pub fn session_usable(s: Option<&Session>) -> Result<()> {
    let Some(s) = s else {
        return Err(Error::SessionNotFound);
    };
    if s.is_deleted {
        return Err(Error::SessionNotFound);
    }
    if let Some(expires_at) = s.expires_at {
        if Utc::now() > expires_at {
            return Err(Error::SessionExpired);
        }
    }
    Ok(())
}

/// Pulls a refresh token out of the JSON body. Errors are swallowed: an absent
/// body simply means "no fallback available".
pub(crate) fn body_refresh_token(r: &RequestContext<'_>) -> String {
    #[derive(serde::Deserialize)]
    struct Body {
        #[serde(default)]
        refresh_token: String,
    }
    serde_json::from_slice::<Body>(r.body())
        .map(|body| body.refresh_token)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn session_usable_rejects_dead_sessions() {
        let now = Utc::now();
        let cases: Vec<(&str, Option<Session>, Option<Error>)> = vec![
            ("nil session", None, Some(Error::SessionNotFound)),
            (
                "soft-deleted session",
                Some(Session {
                    id: "s1".into(),
                    is_deleted: true,
                    expires_at: Some(now + Duration::hours(1)),
                    ..Session::default()
                }),
                Some(Error::SessionNotFound),
            ),
            (
                "expired session",
                Some(Session {
                    id: "s1".into(),
                    expires_at: Some(now - Duration::minutes(1)),
                    ..Session::default()
                }),
                Some(Error::SessionExpired),
            ),
            (
                "active session",
                Some(Session {
                    id: "s1".into(),
                    expires_at: Some(now + Duration::hours(1)),
                    ..Session::default()
                }),
                None,
            ),
            (
                "zero expiry never expires",
                Some(Session {
                    id: "s1".into(),
                    ..Session::default()
                }),
                None,
            ),
        ];

        for (name, session, want) in cases {
            let got = session_usable(session.as_ref());
            match want {
                None => assert!(got.is_ok(), "{name}: expected ok, got {got:?}"),
                Some(Error::SessionNotFound) => {
                    assert!(
                        matches!(got, Err(Error::SessionNotFound)),
                        "{name}: got {got:?}"
                    );
                }
                Some(Error::SessionExpired) => {
                    assert!(
                        matches!(got, Err(Error::SessionExpired)),
                        "{name}: got {got:?}"
                    );
                }
                Some(other) => panic!("{name}: unexpected expectation {other:?}"),
            }
        }
    }
}
