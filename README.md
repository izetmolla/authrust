# authrust

Framework-agnostic authentication and authorization for Rust, built on `http` and `tower`. It provides OAuth 2.0 / OpenID Connect sign-in (Google, Azure AD, ...), credentials and LDAP authentication, JWT access/refresh tokens, database-backed sessions (`sqlx` + PostgreSQL) with optional Redis caching, cookie handling, CSRF protection, and role-based access control.

This is a port of the Go [`goauth`](https://github.com/izetmolla/goauth) module and keeps its structure and naming: `goauth.New(&goauth.Config{...})` becomes `Authorization::new(Config { .. })`, `auth.UseAPIAuthorization(...)` becomes `auth.use_api_authorization([..])`, and so on.

Because the middlewares are `tower` layers and the endpoints are plain `http` handlers, authrust plugs into any `tower`-based stack — [axum](examples/axum/README.md), tonic, hyper directly — and into everything else through two small adapters (see the [actix-web example](examples/actix/README.md)).

## Features

- **OAuth 2.0 / OIDC sign-in** with discovery, PKCE, `state`, and `nonce` checks
- **Provider presets**: Google, Azure AD / Entra ID, credentials, LDAP / Active Directory
- **JWT tokens**: HS256/HS384/HS512 access + refresh token pairs with configurable lifetimes (`"60s"`, `"15m"`, `"7d"`, `"1y"`, ...)
- **Sessions**: persisted with `sqlx` against PostgreSQL, optionally cached in Redis
- **Two protection modes**: Bearer JWT for APIs and session cookie (with sign-in redirect) for server-rendered pages
- **Role-based access control** with `name:perms` grants (`"admin:rw"`, `"hr:r"`)
- **Provider connect flow** for linking extra OAuth scopes or accounts to an existing user
- **Security**: signed double-submit CSRF cookies, `__Host-`/`__Secure-` cookie prefixes, cross-subdomain SSO cookies, PBKDF2-SHA256 password hashing

## Installation

```toml
[dependencies]
authrust = "0.1"
```

The `axum` feature (enabled by default) adds `Authorization::handler()`, which returns an `axum::Router`. Turn it off with `default-features = false` when you are not using axum.

## Quick start

```rust,no_run
use std::sync::Arc;
use authrust::{Authorization, Config, JsonbArray, User, providers::google};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;

    let auth = Authorization::new(Config {
        jwt_secret: "change-me".into(),           // required — HMAC signing secret
        auth_url: "https://app.example.com".into(), // external base URL
        db: Some(pool),                           // required (users + sessions)
        providers: vec![google::new("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")],
        // Map the raw provider profile onto a user in YOUR database.
        resolve_user: Some(Arc::new(|profile| {
            Box::pin(async move {
                // look up / provision by profile["email"], profile["sub"], ...
                let _ = profile;
                Ok((Some(User {
                    id: "uuid".into(),
                    roles: JsonbArray::from_iter(["admin:rw"]),
                    ..User::default()
                }), false))
            })
        })),
        ..Config::default()
    })?;

    let app = axum::Router::new()
        // All auth endpoints in one line (see "HTTP endpoints" below).
        .merge(auth.handler())
        // A JWT-protected API route.
        .merge(
            axum::Router::new()
                .route("/api/profile", axum::routing::get(|| async { "profile" }))
                .layer(auth.use_api_authorization([])),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

The database schema authrust expects is in [`examples/schema.sql`](examples/schema.sql).

## HTTP endpoints

`auth.handler()` returns a router serving everything under `authrust::DEFAULT_BASE_PATH` (`/api/authorization`):

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `GET` | `{base}/providers` | `get_providers` | JSON list of configured providers (Auth.js-compatible shape) |
| `ANY` | `{base}/provider/{provider}` | `handle_sign_in` | Starts the sign-in flow (OAuth redirect, or credentials POST) |
| `ANY` | `{base}/provider/{provider}/callback` | `handle_callback` | OAuth/OIDC callback; validates state/PKCE/nonce, exchanges the code, resolves the user, creates the session, and renders the callback page |

The three handlers are also public individually if you prefer to register the routes yourself, and `auth.route(request)` dispatches between them for routers that only offer a catch-all (see the actix-web example).

Useful query parameters on the sign-in endpoint:

- `?json=true` (or header `X-Auth-Return-Redirect: 1` / `Accept: application/json`) — return the authorization URL as JSON instead of a 302 redirect
- `?flow=token` (or header `X-Auth-Flow: token`) — token flow for mobile/API clients
- `?connect=1&resource_id=<uuid>` — provider **connect** flow: link the OAuth account and scopes to an existing user; on completion the `Config::on_provider_connect` callback runs

## Middlewares

All middlewares are `tower` layers:

```rust,no_run
# use authrust::Authorization;
# fn demo(auth: &Authorization) {
// Bearer JWT (Authorization header or ?access_token=) for APIs.
auth.use_api_authorization([
    auth.with_roles(["admin"]),                 // optional role gate
    auth.with_excluded_paths(["/api/public"]),  // optional path prefixes to skip
]);

// Session cookie for server-rendered pages; unauthenticated requests are
// redirected to Config::sign_in_redirect_url with ?redirectUrl=<original>.
auth.use_web_authorization([]);

// Refresh-token endpoint layer: activates only when the client sends the
// opt-in header (authrust::REFRESH_TOKEN_HANDLER_IDENTIFIER, "cft"),
// otherwise passes the request through to the inner service.
auth.handle_refresh_token();
# }
```

Inside a protected handler, build a `RequestContext` from the request head and ask:

```rust,no_run
# use authrust::{Authorization, http::RequestContext};
# async fn demo(auth: &Authorization, parts: &http::request::Parts) {
let r = RequestContext::new(parts);

let claims = auth.get_claims(&r);              // the validated token's claims
let roles = auth.get_roles(&r);                // Vec<String> from the "roles" claim
let data = auth.get_auth_data_api(&r);         // AuthData { session_id, user_id, roles }
let data = auth.get_auth_data_web(&r).await;   // same, resolved from the session cookie
# }
```

## Configuration

```rust,no_run
# use std::time::Duration;
# use authrust::{Config, CookieOptions};
Config {
    jwt_secret: "...".into(),                 // required — HMAC signing secret
    auth_url: "https://...".into(),           // external origin; falls back to request headers
    signing_method: "HS256".into(),           // HS256 (default) | HS384 | HS512
    access_token_duration: "60s".into(),      // s/m/h/d/w/mo/y units supported
    refresh_token_duration: "1y".into(),
    sign_in_redirect_url: "/sign-in".into(),  // target of the WEB middleware redirect

    db: None,                                 // Option<sqlx::PgPool>, required
    redis: None,                              // optional session cache
    redis_prefix: "AUTHSESSIONS".into(),
    redis_ttl: Duration::from_secs(30 * 60),

    user_table_name: "users".into(),          // needs at least: id, roles
    session_table_name: "sessions".into(),    // see examples/schema.sql

    cookie_session_name: "cnf.id".into(),     // WEB session cookie name
    cookies: CookieOptions::default(),        // per-cookie overrides

    providers: vec![],                        // see "Providers" below
    resolve_user: None,                       // required for OAuth sign-in
    on_provider_connect: None,                // optional
};
```

For single sign-on across subdomains (`example.com`, `admin.example.com`, ...):

```rust,no_run
let cookies = authrust::cross_subdomain_cookies(".example.com");
// Config { cookies, .. } — all participating apps must share the same jwt_secret
```

## Tokens, sessions and roles

- `auth.authorize(opts)` creates a session row and signs an access/refresh pair. The OAuth callback does this automatically; call it yourself for custom flows (for example after an LDAP login).
- `auth.check_session(&mut w, &r)` validates a refresh token, refreshes the access token with up-to-date roles, and re-sets the session cookie.
- Roles use the `name:perms` grant format, where perms is `r`, `w`, or `rw`. `auth.get_role(endpoint_roles, user_roles)` returns `(has_role, can_read, can_write)`.
- `authrust::hash_password` / `authrust::check_password` implement PBKDF2-SHA256 (`$pbkdf2-sha256$...`) for credentials storage.

## Framework integration

authrust itself depends on no web framework. Each example is a runnable workspace member with its own README:

| Framework | Example | Adapter needed |
|-----------|---------|----------------|
| axum | [`examples/axum`](examples/axum/README.md) | none — `auth.handler()` is a `Router`, the middlewares are layers |
| actix-web | [`examples/actix`](examples/actix/README.md) | two small functions, included in the example |
| hyper / tonic / any `tower` stack | — | none |

See [`examples/README.md`](examples/README.md) for how to run and test them.

## Providers

| Provider | Module | Type |
|----------|--------|------|
| Google | `providers::google` | OIDC (discovery, PKCE + state + nonce) |
| Azure AD / Entra ID | `providers::azuread` | OIDC v2.0 endpoints, Microsoft Graph profile |
| Credentials | `providers::credentials` | Username/password with a custom `authorize` callback |
| LDAP / Active Directory | `providers::ldap` | Directory bind plus attribute and role mapping |

Any other OAuth/OIDC service can be configured with a plain `OAuthProvider`, and the `Provider` trait is public so you can add your own.

## License

MIT
