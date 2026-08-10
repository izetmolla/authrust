//! Route protection as [`tower_layer::Layer`]s.
//!
//! Use [`Authorization::use_api_authorization`] for Bearer JWT APIs and
//! [`Authorization::use_web_authorization`] for session-cookie web routes.
//! Compatible with axum, hyper, tonic, and other `tower` stacks.

use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use jsonwebtoken::decode;
use serde_json::{Map as JsonMap, Value, json};
use tower_layer::Layer;
use tower_service::Service;

use crate::authorization::Authorization;
use crate::claims::{JwtToken, with_jwt};
use crate::cookies::read_cookie;
use crate::errors::{BoxError, Error, Result};
use crate::http::{RequestContext, is_secure_request};
use crate::options::{AuthConfig, AuthConfigOptions, new_auth_config_options};
use crate::response::{BoxedResponse, into_boxed, redirect, write_json};
use crate::roles::{format_roles, roles_from_any};
use crate::utils::is_excluded_path;

/// Pulls the JWT from the `Authorization` header (Bearer scheme) or, as a
/// fallback, from the `access_token` query parameter.
pub fn extract_bearer_token(r: &RequestContext<'_>) -> String {
    let auth = r.header("authorization");
    if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("Bearer ") {
        return auth[7..].to_string();
    }
    r.query_get("access_token").to_string()
}

impl Authorization {
    /// Validates a raw token against the configured secret and returns it.
    pub fn parse_jwt(&self, raw: &str) -> Result<JwtToken> {
        if raw.is_empty() {
            return Err(Error::msg("missing or malformed JWT"));
        }
        let data = decode::<JsonMap<String, Value>>(raw, &self.decoding_key(), &self.validation())
            .map_err(|_| Error::msg("invalid or expired JWT"))?;
        Ok(JwtToken {
            header: data.header,
            claims: data.claims,
        })
    }

    /// Returns a layer that protects API routes with a Bearer JWT.
    ///
    /// On success the validated token is stored on the request extensions (see
    /// [`Authorization::get_claims`] and [`crate::claims::jwt_from_context`]);
    /// optional roles are enforced.
    pub fn use_api_authorization(
        &self,
        opts: impl IntoIterator<Item = AuthConfigOptions>,
    ) -> ApiAuthorizationLayer {
        ApiAuthorizationLayer {
            auth: self.clone(),
            cfg: Arc::new(new_auth_config_options(opts)),
        }
    }

    /// Returns a layer that protects WEB routes with a session cookie.
    ///
    /// Missing or invalid cookies are redirected to the sign-in URL, preserving
    /// the original request URL in `redirectUrl`.
    pub fn use_web_authorization(
        &self,
        opts: impl IntoIterator<Item = AuthConfigOptions>,
    ) -> WebAuthorizationLayer {
        WebAuthorizationLayer {
            auth: self.clone(),
            cfg: Arc::new(new_auth_config_options(opts)),
        }
    }

    /// Builds the sign-in URL with a `redirectUrl` query parameter pointing back
    /// at the original request, preserving the browser scheme.
    pub fn get_auth_redirect_url(&self, r: &RequestContext<'_>) -> String {
        let scheme = if is_secure_request(r) {
            "https"
        } else {
            "http"
        };
        let original = format!("{scheme}://{}{}", r.host(), r.request_uri());
        let escaped: String = form_urlencoded::byte_serialize(original.as_bytes()).collect();
        format!("{}?redirectUrl={escaped}", self.sign_in_redirect_url())
    }
}

fn insufficient_permissions(roles: &[String]) -> crate::response::Response {
    write_json(
        StatusCode::FORBIDDEN,
        json!({
            "error": format!("insufficient permissions: {}", roles.join(", ")),
            "code": "INSUFFICIENT_PERMISSIONS",
        }),
    )
}

fn server_error(message: String) -> crate::response::Response {
    write_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({ "error": message, "code": "SERVER_ERROR" }),
    )
}

// --- API middleware --------------------------------------------------------

/// Layer produced by [`Authorization::use_api_authorization`].
#[derive(Clone, Debug)]
pub struct ApiAuthorizationLayer {
    auth: Authorization,
    cfg: Arc<AuthConfig>,
}

impl<S> Layer<S> for ApiAuthorizationLayer {
    type Service = ApiAuthorization<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiAuthorization {
            inner,
            auth: self.auth.clone(),
            cfg: self.cfg.clone(),
        }
    }
}

/// Service produced by [`ApiAuthorizationLayer`].
#[derive(Clone, Debug)]
pub struct ApiAuthorization<S> {
    inner: S,
    auth: Authorization,
    cfg: Arc<AuthConfig>,
}

/// Decides what to do with an API request: skip it, let it through with a
/// validated token, or reject it outright.
fn api_outcome(
    auth: &Authorization,
    cfg: &AuthConfig,
    r: &RequestContext<'_>,
) -> std::result::Result<Option<JwtToken>, Box<crate::response::Response>> {
    if is_excluded_path(&cfg.excluded_paths, r.path()) {
        return Ok(None);
    }

    let token = auth.parse_jwt(&extract_bearer_token(r)).map_err(|err| {
        Box::new(write_json(
            StatusCode::UNAUTHORIZED,
            json!({ "error": err.to_string(), "code": "UNAUTHORIZED" }),
        ))
    })?;

    if !cfg.roles.is_empty() {
        let roles = match token.claims.get("roles") {
            None | Some(Value::Null) => Err(Error::InvalidRoles),
            Some(raw) => roles_from_any(raw),
        }
        .map_err(|err| Box::new(server_error(err.to_string())))?;

        let (has_role, _, _) = auth.get_role(&cfg.roles, &roles);
        if !has_role {
            return Err(Box::new(insufficient_permissions(&cfg.roles)));
        }
    }

    Ok(Some(token))
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ApiAuthorization<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = BoxedResponse;
    type Error = S::Error;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // The service that was polled ready is the one that must be called.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.auth.clone();
        let cfg = self.cfg.clone();

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            let outcome = {
                let r = RequestContext::new(&parts);
                api_outcome(&auth, &cfg, &r)
            };
            match outcome {
                Err(response) => return Ok(into_boxed(*response)),
                Ok(Some(token)) => with_jwt(&mut parts.extensions, token),
                Ok(None) => {}
            }
            inner
                .call(Request::from_parts(parts, body))
                .await
                .map(into_boxed)
        })
    }
}

// --- WEB middleware --------------------------------------------------------

/// Layer produced by [`Authorization::use_web_authorization`].
#[derive(Clone, Debug)]
pub struct WebAuthorizationLayer {
    auth: Authorization,
    cfg: Arc<AuthConfig>,
}

impl<S> Layer<S> for WebAuthorizationLayer {
    type Service = WebAuthorization<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebAuthorization {
            inner,
            auth: self.auth.clone(),
            cfg: self.cfg.clone(),
        }
    }
}

/// Service produced by [`WebAuthorizationLayer`].
#[derive(Clone, Debug)]
pub struct WebAuthorization<S> {
    inner: S,
    auth: Authorization,
    cfg: Arc<AuthConfig>,
}

async fn web_outcome(
    auth: &Authorization,
    cfg: &AuthConfig,
    r: &RequestContext<'_>,
) -> std::result::Result<(), crate::response::Response> {
    if is_excluded_path(&cfg.excluded_paths, r.path()) {
        return Ok(());
    }

    let session_id = read_cookie(r, auth.cookie_session_name());
    if session_id.is_empty() {
        return Err(redirect(
            StatusCode::TEMPORARY_REDIRECT,
            &auth.get_auth_redirect_url(r),
        ));
    }

    let session = match auth.get_session(&session_id).await {
        Ok(session) => session,
        Err(err) if err.is_session_missing() || err.is_session_expired() => {
            return Err(redirect(
                StatusCode::TEMPORARY_REDIRECT,
                &auth.get_auth_redirect_url(r),
            ));
        }
        Err(err) => return Err(server_error(err.to_string())),
    };

    if !cfg.roles.is_empty() {
        let user_roles = format_roles(&session.user.roles);
        let (has_role, _, _) = auth.get_role(&cfg.roles, &user_roles);
        if !has_role {
            return Err(insufficient_permissions(&cfg.roles));
        }
    }

    Ok(())
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for WebAuthorization<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = BoxedResponse;
    type Error = S::Error;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let auth = self.auth.clone();
        let cfg = self.cfg.clone();

        Box::pin(async move {
            let (parts, body) = req.into_parts();
            {
                let r = RequestContext::new(&parts);
                if let Err(response) = web_outcome(&auth, &cfg, &r).await {
                    return Ok(into_boxed(response));
                }
            }
            inner
                .call(Request::from_parts(parts, body))
                .await
                .map(into_boxed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Config;
    use chrono::Utc;
    use http_body_util::Full;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tower::{ServiceExt, service_fn};

    fn sign_test_access_token(secret: &str, roles: Value) -> String {
        let now = Utc::now().timestamp();
        let claims = json!({
            "user_id": "user-1",
            "roles": roles,
            "exp": now + 60,
            "iat": now,
        });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign test token")
    }

    fn test_authorization(secret: &str) -> Authorization {
        Authorization::from_config_unchecked(Config {
            jwt_secret: secret.to_string(),
            ..Config::default()
        })
    }

    async fn ok_service(
        _req: Request<Full<Bytes>>,
    ) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap())
    }

    #[tokio::test]
    async fn use_api_authorization_enforces_tokens_and_roles() {
        const SECRET: &str = "test-secret";
        let a = test_authorization(SECRET);

        let cases: Vec<(&str, String, StatusCode)> = vec![
            (
                "valid token with matching role",
                format!(
                    "Bearer {}",
                    sign_test_access_token(SECRET, json!(["admin:rw"]))
                ),
                StatusCode::OK,
            ),
            (
                // Regression: a null entry in the roles claim used to bubble up
                // as a 500.
                "roles claim containing null entries",
                format!(
                    "Bearer {}",
                    sign_test_access_token(SECRET, json!([null, "admin:rw"]))
                ),
                StatusCode::OK,
            ),
            (
                // Regression: a JSON-encoded roles string used to be wrapped as
                // a single garbage grant, denying access.
                "roles claim as json-encoded string",
                format!(
                    "Bearer {}",
                    sign_test_access_token(SECRET, json!(r#"["admin:rw","hr:r"]"#))
                ),
                StatusCode::OK,
            ),
            (
                "valid token without required role",
                format!("Bearer {}", sign_test_access_token(SECRET, json!(["hr:r"]))),
                StatusCode::FORBIDDEN,
            ),
            ("missing token", String::new(), StatusCode::UNAUTHORIZED),
            (
                "token signed with wrong secret",
                format!(
                    "Bearer {}",
                    sign_test_access_token("other-secret", json!(["admin:rw"]))
                ),
                StatusCode::UNAUTHORIZED,
            ),
        ];

        for (name, auth_header, want_status) in cases {
            let protected = a
                .use_api_authorization([a.with_roles(["admin"])])
                .layer(service_fn(ok_service));

            let mut builder = Request::builder().method("GET").uri("/protected");
            if !auth_header.is_empty() {
                builder = builder.header("Authorization", auth_header);
            }
            let request = builder.body(Full::new(Bytes::new())).unwrap();

            let response = protected.oneshot(request).await.unwrap();
            assert_eq!(response.status(), want_status, "{name}");
        }
    }

    #[tokio::test]
    async fn use_api_authorization_skips_excluded_paths() {
        let a = test_authorization("test-secret");
        let protected = a
            .use_api_authorization([a.with_excluded_paths(["/public"])])
            .layer(service_fn(ok_service));

        let request = Request::builder()
            .method("GET")
            .uri("/public/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response = protected.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
