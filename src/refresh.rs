//! The opt-in refresh-token endpoint middleware.

use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower_layer::Layer;
use tower_service::Service;

use crate::authorization::Authorization;
use crate::constants::REFRESH_TOKEN_HANDLER_IDENTIFIER;
use crate::errors::{BoxError, Error};
use crate::http::RequestContext;
use crate::response::{BoxedResponse, into_boxed, write_json};
use crate::session_check::body_refresh_token;

impl Authorization {
    /// Returns a layer that conditionally handles refresh-token requests.
    ///
    /// The request is only handled when the client opts in by setting the
    /// [`REFRESH_TOKEN_HANDLER_IDENTIFIER`] header; every other request is
    /// forwarded to the inner service.
    ///
    /// On success the response body is the new access token; on failure a JSON
    /// envelope with an error message and machine-readable code is returned.
    pub fn handle_refresh_token(&self) -> RefreshTokenLayer {
        RefreshTokenLayer { auth: self.clone() }
    }
}

/// Layer produced by [`Authorization::handle_refresh_token`].
#[derive(Clone, Debug)]
pub struct RefreshTokenLayer {
    auth: Authorization,
}

impl<S> Layer<S> for RefreshTokenLayer {
    type Service = RefreshToken<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RefreshToken {
            inner,
            auth: self.auth.clone(),
        }
    }
}

/// Service produced by [`RefreshTokenLayer`].
#[derive(Clone, Debug)]
pub struct RefreshToken<S> {
    inner: S,
    auth: Authorization,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RefreshToken<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: http_body::Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
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

        let opted_in = req
            .headers()
            .get(REFRESH_TOKEN_HANDLER_IDENTIFIER)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.is_empty() && value != "no");

        Box::pin(async move {
            if !opted_in {
                return inner.call(req).await.map(into_boxed);
            }

            let (parts, body) = req.into_parts();
            let bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            let r = RequestContext::with_body(&parts, bytes);
            Ok(into_boxed(refresh_response(&auth, &r).await))
        })
    }
}

async fn refresh_response(
    auth: &Authorization,
    r: &RequestContext<'_>,
) -> crate::response::Response {
    let refresh_token = match auth.get_token_from_header(r.header("authorization")) {
        Ok(token) => token,
        Err(_) => body_refresh_token(r),
    };
    if refresh_token.is_empty() {
        return write_json(
            StatusCode::UNAUTHORIZED,
            json!({
                "error": Error::MissingRefreshToken.to_string(),
                "code": "TOKEN_INVALID",
            }),
        );
    }

    let claims = match auth.extract_token(&refresh_token) {
        Ok(claims) => claims,
        Err(err) => {
            return write_json(
                StatusCode::UNAUTHORIZED,
                json!({ "error": err.to_string(), "code": "TOKEN_INVALID" }),
            );
        }
    };

    let session = match auth.get_session(&claims.session_id).await {
        Ok(session) => session,
        Err(err) if err.is_session_missing() => {
            return write_json(
                StatusCode::UNAUTHORIZED,
                json!({
                    "error": Error::SessionNotFound.to_string(),
                    "code": "UNAUTHORIZED",
                }),
            );
        }
        Err(err) if err.is_session_expired() => {
            return write_json(
                StatusCode::UNAUTHORIZED,
                json!({
                    "error": Error::SessionExpired.to_string(),
                    "code": "UNAUTHORIZED",
                }),
            );
        }
        Err(err) => {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": err.to_string(), "code": "SERVER_ERROR" }),
            );
        }
    };

    match auth.refresh_access_token(&claims, &session, []) {
        Ok(access_token) => write_json(StatusCode::OK, access_token),
        Err(err) => write_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": err.to_string(), "code": "SERVER_ERROR" }),
        ),
    }
}
