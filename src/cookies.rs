//! Cookie definitions and helpers.
//!
//! Names follow the Auth.js conventions, including the `__Host-` / `__Secure-`
//! prefixes on HTTPS.

use std::time::Duration;

use cookie::{Cookie, SameSite, time::Duration as CookieDuration};
use http::header::{HeaderValue, SET_COOKIE};

use crate::authorization::Authorization;
use crate::http::RequestContext;
use crate::response::ResponseWriter;

/// Overrides individual cookie definitions. Unset fields fall back to secure
/// defaults derived from the request scheme.
#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    pub session_token: Option<CookieOption>,
    pub callback_url: Option<CookieOption>,
    pub csrf_token: Option<CookieOption>,
    pub pkce_code_verifier: Option<CookieOption>,
    pub state: Option<CookieOption>,
    pub nonce: Option<CookieOption>,
}

/// Returns [`CookieOptions`] that share this crate's cookies across every
/// subdomain of the given parent domain, enabling single sign-on between e.g.
/// `example.com`, `manager.example.com` and `finance.example.com`.
///
/// Pass the registrable domain with a leading dot, e.g. `.example.com`. Only the
/// domain is set on each cookie; the secure defaults (HttpOnly, Secure,
/// SameSite, names and prefixes) are preserved. The CSRF cookie automatically
/// uses the `__Secure-` prefix instead of `__Host-`, which forbids a domain.
///
/// All participating subdomains must use the same secret and the same cookie
/// names.
pub fn cross_subdomain_cookies(domain: &str) -> CookieOptions {
    let with_domain = || {
        Some(CookieOption {
            domain: domain.to_string(),
            ..CookieOption::default()
        })
    };
    CookieOptions {
        session_token: with_domain(),
        callback_url: with_domain(),
        csrf_token: with_domain(),
        pkce_code_verifier: with_domain(),
        state: with_domain(),
        nonce: with_domain(),
    }
}

/// Configures a single cookie.
#[derive(Debug, Clone, Default)]
pub struct CookieOption {
    pub name: String,
    pub http_only: bool,
    /// `None` leaves the attribute unset, so an override does not clobber the
    /// secure default.
    pub same_site: Option<SameSite>,
    pub path: String,
    pub secure: bool,
    /// Zero leaves the cookie as a session cookie.
    pub max_age: Duration,
    pub domain: String,
}

/// Resolves the concrete cookie definitions for a request, choosing the
/// `__Secure-` / `__Host-` prefixed names on HTTPS.
#[derive(Debug, Clone)]
pub struct CookieJar {
    secure: bool,
    opts: CookieOptions,
}

impl CookieJar {
    /// Builds a jar for a request of the given scheme.
    pub fn new(secure: bool, opts: CookieOptions) -> Self {
        Self { secure, opts }
    }

    fn prefix(&self, host: bool) -> &'static str {
        if !self.secure {
            return "";
        }
        if host { "__Host-" } else { "__Secure-" }
    }

    /// Merges an optional override onto the secure base definition.
    ///
    /// Only fields explicitly set on the override take effect, so callers can
    /// set just a domain (for cross-subdomain sharing) without discarding
    /// HttpOnly, Secure, SameSite and the rest. Booleans can only be turned on,
    /// never off, to avoid accidentally weakening the defaults.
    fn def(&self, override_opt: Option<&CookieOption>, base: CookieOption) -> CookieOption {
        let mut out = base;
        let Some(o) = override_opt else {
            return out;
        };
        if !o.name.is_empty() {
            out.name = o.name.clone();
        }
        if !o.path.is_empty() {
            out.path = o.path.clone();
        }
        if !o.domain.is_empty() {
            out.domain = o.domain.clone();
        }
        if let Some(same_site) = o.same_site {
            out.same_site = Some(same_site);
        }
        if !o.max_age.is_zero() {
            out.max_age = o.max_age;
        }
        out.http_only = out.http_only || o.http_only;
        out.secure = out.secure || o.secure;
        out
    }

    fn base(&self, name: String, max_age: Duration) -> CookieOption {
        CookieOption {
            name,
            http_only: true,
            same_site: Some(SameSite::Lax),
            path: "/".to_string(),
            secure: self.secure,
            max_age,
            domain: String::new(),
        }
    }

    /// The cookie holding the post-sign-in redirect target.
    pub fn callback_url(&self) -> CookieOption {
        let base = self.base(
            format!("{}authjs.callback-url", self.prefix(false)),
            Duration::ZERO,
        );
        self.def(self.opts.callback_url.as_ref(), base)
    }

    /// The signed double-submit CSRF cookie.
    ///
    /// It normally uses the `__Host-` prefix, which locks the cookie to the
    /// exact host. That prefix forbids a domain attribute, so when a domain is
    /// configured (for cross-subdomain sharing) it falls back to `__Secure-`,
    /// which permits one.
    pub fn csrf_token(&self) -> CookieOption {
        let host = !self
            .opts
            .csrf_token
            .as_ref()
            .is_some_and(|opt| !opt.domain.is_empty());
        let base = self.base(
            format!("{}authjs.csrf-token", self.prefix(host)),
            Duration::ZERO,
        );
        self.def(self.opts.csrf_token.as_ref(), base)
    }

    /// The cookie holding the PKCE code verifier.
    pub fn pkce_code_verifier(&self) -> CookieOption {
        let base = self.base(
            format!("{}authjs.pkce.code_verifier", self.prefix(false)),
            Duration::from_secs(15 * 60),
        );
        self.def(self.opts.pkce_code_verifier.as_ref(), base)
    }

    /// The cookie holding the OAuth `state` value.
    pub fn state(&self) -> CookieOption {
        let base = self.base(
            format!("{}authjs.state", self.prefix(false)),
            Duration::from_secs(15 * 60),
        );
        self.def(self.opts.state.as_ref(), base)
    }

    /// The cookie remembering a token-flow preference across the OAuth
    /// round-trip.
    pub fn flow(&self) -> CookieOption {
        self.base(
            format!("{}authjs.flow", self.prefix(false)),
            Duration::from_secs(15 * 60),
        )
    }

    /// The cookie carrying the signed flow intent (e.g. `connect`).
    pub fn flow_intent(&self) -> CookieOption {
        self.base(
            format!("{}authjs.flow-intent", self.prefix(false)),
            Duration::from_secs(15 * 60),
        )
    }

    /// The cookie carrying the provider-connect target resource id.
    pub fn connect_resource(&self) -> CookieOption {
        self.base(
            format!("{}authjs.connect-resource", self.prefix(false)),
            Duration::from_secs(15 * 60),
        )
    }

    /// The cookie holding the OIDC `nonce` value.
    pub fn nonce(&self) -> CookieOption {
        let base = self.base(
            format!("{}authjs.nonce", self.prefix(false)),
            Duration::from_secs(15 * 60),
        );
        self.def(self.opts.nonce.as_ref(), base)
    }

    /// Clears the transient OAuth cookies so they do not accumulate across
    /// repeated sign-in attempts and inflate the `Cookie` header.
    pub fn expire_oauth_flow_cookies(&self, w: &mut ResponseWriter) {
        expire_cookie(w, &self.state());
        expire_cookie(w, &self.pkce_code_verifier());
        expire_cookie(w, &self.nonce());
        expire_cookie(w, &self.callback_url());
        expire_cookie(w, &self.flow());
        expire_cookie(w, &self.connect_resource());
    }
}

fn build_cookie(opt: &CookieOption, value: &str) -> Cookie<'static> {
    let mut builder = Cookie::build((opt.name.clone(), value.to_string()))
        .http_only(opt.http_only)
        .secure(opt.secure);
    if !opt.path.is_empty() {
        builder = builder.path(opt.path.clone());
    }
    if !opt.domain.is_empty() {
        builder = builder.domain(opt.domain.clone());
    }
    if let Some(same_site) = opt.same_site {
        builder = builder.same_site(same_site);
    }
    builder.build()
}

/// Writes a cookie with the given value. A zero `max_age` leaves it as a
/// session cookie.
pub fn set_cookie(w: &mut ResponseWriter, opt: &CookieOption, value: &str) {
    let mut cookie = build_cookie(opt, value);
    if !opt.max_age.is_zero() {
        let seconds = opt.max_age.as_secs().min(i64::MAX as u64) as i64;
        cookie.set_max_age(CookieDuration::seconds(seconds));
        cookie.set_expires(
            cookie::time::OffsetDateTime::now_utc() + CookieDuration::seconds(seconds),
        );
    }
    append_cookie(w, &cookie);
}

/// Removes a cookie by setting it to an immediately-expired empty value.
pub fn expire_cookie(w: &mut ResponseWriter, opt: &CookieOption) {
    let mut cookie = build_cookie(opt, "");
    cookie.set_max_age(CookieDuration::seconds(-1));
    cookie.set_expires(cookie::time::OffsetDateTime::UNIX_EPOCH);
    append_cookie(w, &cookie);
}

fn append_cookie(w: &mut ResponseWriter, cookie: &Cookie<'static>) {
    if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
        w.append(SET_COOKIE, value);
    }
}

/// Returns the value of the named cookie, or `""`.
pub fn read_cookie(r: &RequestContext<'_>, name: &str) -> String {
    for header in r.headers().get_all(http::header::COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for cookie in Cookie::split_parse(raw).flatten() {
            if cookie.name() == name {
                return cookie.value().to_string();
            }
        }
    }
    String::new()
}

impl Authorization {
    /// Builds the per-request cookie jar.
    pub fn jar(&self, secure: bool) -> CookieJar {
        CookieJar::new(secure, self.cookies().clone())
    }
}
