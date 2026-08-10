//! Response construction: JSON envelopes, redirects and the header buffer that
//! stands in for Go's `http.ResponseWriter`.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body::{Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use serde_json::json;

use crate::authorization::Authorization;
use crate::errors::BoxError;
use crate::http::RequestContext;

/// Body type of every response this crate produces. All payloads are buffered
/// in memory, so a `Full<Bytes>` is always sufficient.
pub type Body = Full<Bytes>;

/// Response type of every handler in this crate.
pub type Response = http::Response<Body>;

/// Erased body type returned by the middlewares, which must unify their own
/// error responses with the inner service's body.
///
/// `http_body_util::BoxBody` also demands `Sync`, which framework bodies such as
/// axum's do not implement, while `UnsyncBoxBody` is not `Send`, which routers
/// require. This box asks for exactly `Send`.
pub struct BoxedBody(Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send>>);

impl BoxedBody {
    /// Erases the type of a response body.
    pub fn new<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        Self(Box::pin(body.map_err(Into::into)))
    }
}

impl fmt::Debug for BoxedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedBody").finish_non_exhaustive()
    }
}

impl http_body::Body for BoxedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        self.0.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// Response type returned by the middlewares.
pub type BoxedResponse = http::Response<BoxedBody>;

/// A shorthand for JSON object payloads, mirroring Go's `Map`.
pub type Map = serde_json::Map<String, serde_json::Value>;

/// Erases a response body so a middleware can return either its own error
/// response or the inner service's response.
pub fn into_boxed<B>(response: http::Response<B>) -> BoxedResponse
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    response.map(BoxedBody::new)
}

/// Collects headers written while a handler runs, then applies them to the
/// finished response. Go writes cookies straight to the `http.ResponseWriter`
/// before the body; Rust builds the response last, so they are buffered here.
#[derive(Debug, Default)]
pub struct ResponseWriter {
    headers: HeaderMap,
}

impl ResponseWriter {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The buffered headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Mutable access to the buffered headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Appends a header value, keeping any previously buffered values. Used for
    /// `Set-Cookie`, which legitimately repeats.
    pub fn append(&mut self, name: header::HeaderName, value: HeaderValue) {
        self.headers.append(name, value);
    }

    /// Copies every buffered header onto a finished response.
    pub fn apply<B>(&self, response: &mut http::Response<B>) {
        for (name, value) in self.headers.iter() {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }

    /// Applies the buffered headers and returns the response, for use as the
    /// last expression of a handler.
    pub fn finish<B>(&self, mut response: http::Response<B>) -> http::Response<B> {
        self.apply(&mut response);
        response
    }
}

/// Serializes `v` as the JSON response body with the given status code.
pub fn write_json<T: Serialize>(status: StatusCode, v: T) -> Response {
    let body = match serde_json::to_vec(&v) {
        Ok(body) => body,
        Err(err) => {
            return http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .body(Full::new(Bytes::from(
                    json!({ "error": err.to_string(), "code": "SERVER_ERROR" }).to_string(),
                )))
                .expect("static response is valid");
        }
    };
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("json response is valid")
}

/// Builds a redirect response to `target`.
pub fn redirect(status: StatusCode, target: &str) -> Response {
    let location = HeaderValue::from_str(target).unwrap_or_else(|_| HeaderValue::from_static("/"));
    http::Response::builder()
        .status(status)
        .header(header::LOCATION, location)
        .body(Full::new(Bytes::new()))
        .expect("redirect response is valid")
}

/// Reports whether the client prefers a JSON response over a redirect.
pub fn wants_json(r: &RequestContext<'_>) -> bool {
    if r.header("accept") == "application/json" {
        return true;
    }
    r.header("x-auth-return-redirect") == "1" || r.query_get("json") == "true"
}

impl Authorization {
    /// Either issues an HTTP redirect or returns the target URL as JSON,
    /// matching the Auth.js client convention (`X-Auth-Return-Redirect`).
    pub fn redirect_or_json(&self, r: &RequestContext<'_>, target: &str) -> Response {
        if wants_json(r) {
            return write_json(StatusCode::OK, json!({ "url": target }));
        }
        redirect(StatusCode::FOUND, target)
    }
}
