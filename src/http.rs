//! Request plumbing shared by the handlers and middlewares.
//!
//! [`RequestContext`] is a read-only view over [`http::request::Parts`] plus an
//! optionally collected body (method, URL, headers, cookies, form, peer address).

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{HeaderMap, Method, Uri, request::Parts, uri::Scheme};

/// Peer address of the connection.
///
/// tower services do not carry the socket address, so servers must insert this
/// extension for [`client_ip`] to fall back to it (axum users can copy it out of
/// `ConnectInfo<SocketAddr>`). Proxy headers are preferred when present.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

/// Marks the connection as TLS-terminated by this server.
///
/// Insert this extension when serving HTTPS directly; requests arriving through
/// a reverse proxy are detected via `X-Forwarded-Proto` instead.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionSecure(pub bool);

/// A read-only view of an incoming request.
pub struct RequestContext<'a> {
    parts: &'a Parts,
    query: HashMap<String, Vec<String>>,
    form: HashMap<String, Vec<String>>,
    body: Bytes,
}

impl<'a> RequestContext<'a> {
    /// Builds a context from request head only. Form values are unavailable;
    /// [`RequestContext::form_value`] falls back to the query string.
    pub fn new(parts: &'a Parts) -> Self {
        Self {
            query: parse_query(parts.uri.query().unwrap_or_default()),
            parts,
            form: HashMap::new(),
            body: Bytes::new(),
        }
    }

    /// Builds a context from a request head and its collected body, parsing
    /// `application/x-www-form-urlencoded` payloads into form values. This is
    /// the analogue of Go's implicit `ParseForm`.
    pub fn with_body(parts: &'a Parts, body: Bytes) -> Self {
        let mut ctx = Self::new(parts);
        if ctx.is_form_content_type() && !body.is_empty() {
            if let Ok(text) = std::str::from_utf8(&body) {
                ctx.form = parse_query(text);
            }
        }
        ctx.body = body;
        ctx
    }

    fn is_form_content_type(&self) -> bool {
        self.header("content-type")
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }

    /// The request head.
    pub fn parts(&self) -> &Parts {
        self.parts
    }

    /// The raw request body, empty unless the context was built with one.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The request method.
    pub fn method(&self) -> &Method {
        &self.parts.method
    }

    /// The request URI.
    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// The request path, without the query string.
    pub fn path(&self) -> &str {
        self.parts.uri.path()
    }

    /// The path and query string, matching Go's `URL.RequestURI()`.
    pub fn request_uri(&self) -> String {
        match self.parts.uri.query() {
            Some(query) => format!("{}?{}", self.path(), query),
            None => self.path().to_string(),
        }
    }

    /// All request headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// The value of a header, or `""` when absent.
    pub fn header(&self, name: &str) -> &str {
        self.parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    /// The `Host` header, falling back to the URI authority.
    pub fn host(&self) -> &str {
        let host = self.header("host");
        if !host.is_empty() {
            return host;
        }
        self.parts
            .uri
            .authority()
            .map(|a| a.as_str())
            .unwrap_or_default()
    }

    /// The `User-Agent` header.
    pub fn user_agent(&self) -> &str {
        self.header("user-agent")
    }

    /// The first value of a query parameter, or `""`.
    pub fn query_get(&self, key: &str) -> &str {
        self.query
            .get(key)
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// The first value of a form field, falling back to the query string, or
    /// `""`. This mirrors Go's `Request.FormValue`.
    pub fn form_value(&self, key: &str) -> &str {
        self.form
            .get(key)
            .and_then(|values| values.first())
            .map(String::as_str)
            .unwrap_or_else(|| self.query_get(key))
    }

    /// Every parsed query parameter.
    pub fn query(&self) -> &HashMap<String, Vec<String>> {
        &self.query
    }

    /// Every parsed form field.
    pub fn post_form(&self) -> &HashMap<String, Vec<String>> {
        &self.form
    }

    /// Request extensions, the analogue of Go's request context values.
    pub fn extensions(&self) -> &http::Extensions {
        &self.parts.extensions
    }

    /// The peer address, when the server inserted a [`ClientAddr`] extension.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.parts.extensions.get::<ClientAddr>().map(|addr| addr.0)
    }
}

fn parse_query(raw: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        out.entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    out
}

/// Resolves the `{provider}` route parameter from the request path.
///
/// Go prefers `ServeMux` path values and falls back to splitting the path; this
/// port always splits the path so the handlers work under any router.
pub fn provider_id_from_request(r: &RequestContext<'_>) -> String {
    let path = r.path().trim_matches('/');
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "provider" && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    String::new()
}

/// Reports whether the request arrived over HTTPS, honouring the
/// `X-Forwarded-Proto` header set by reverse proxies.
pub fn is_secure_request(r: &RequestContext<'_>) -> bool {
    if let Some(ConnectionSecure(secure)) = r.extensions().get::<ConnectionSecure>() {
        if *secure {
            return true;
        }
    }
    if r.uri().scheme() == Some(&Scheme::HTTPS) {
        return true;
    }
    r.header("x-forwarded-proto").eq_ignore_ascii_case("https")
}

/// Returns the caller address, preferring proxy-forwarded headers.
pub fn client_ip(r: &RequestContext<'_>) -> String {
    let forwarded = r.header("x-forwarded-for");
    if !forwarded.is_empty() {
        return forwarded
            .split(',')
            .next()
            .unwrap_or(forwarded)
            .trim()
            .to_string();
    }
    let real_ip = r.header("x-real-ip");
    if !real_ip.is_empty() {
        return real_ip.to_string();
    }
    match r.remote_addr() {
        Some(addr) => addr.ip().to_string(),
        None => String::new(),
    }
}
