# authrust

[![Release](https://img.shields.io/crates/v/authrust?label=release&color=brightgreen&logo=github&logoColor=white&labelColor=24292f)](https://crates.io/crates/authrust)
[![CI](https://img.shields.io/github/actions/workflow/status/izetmolla/authrust/ci.yml?branch=main&label=CI&logo=github&logoColor=white&labelColor=24292f)](https://github.com/izetmolla/authrust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?logo=open-source-initiative&logoColor=white&labelColor=24292f)](LICENSE-APACHE)
[![Documentation](https://img.shields.io/badge/documentation-available-brightgreen?logo=readthedocs&logoColor=white&labelColor=24292f)](https://docs.rs/authrust)

Framework-agnostic authentication and authorization for Rust, built on [`http`](https://docs.rs/http) and [`tower`](https://docs.rs/tower).

OAuth 2.0 / OpenID Connect (Google, Azure AD, …), credentials and LDAP, JWT access/refresh tokens, PostgreSQL sessions with optional Redis caching, cookies, CSRF protection, and role-based access control — all as `tower` layers and plain `http` handlers.

**Author:** [Izet Molla](https://github.com/izetmolla)

**Works with:** [axum](examples/axum/README.md) · [actix-web](examples/actix/README.md) · tonic · hyper · any `tower` stack

---

## Features

| Area | What you get |
|------|----------------|
| **OAuth / OIDC** | Discovery, PKCE, `state`, and `nonce` checks |
| **Providers** | Google, Azure AD / Entra ID, credentials, LDAP / Active Directory |
| **JWT** | HS256 / HS384 / HS512 access + refresh pairs (`"60s"`, `"15m"`, `"7d"`, `"1y"`, …) |
| **Sessions** | `sqlx` + PostgreSQL, optional Redis cache |
| **Protection** | Bearer JWT for APIs · session cookie + redirect for web pages |
| **RBAC** | `name:perms` grants (`"admin:rw"`, `"hr:r"`) |
| **Connect flow** | Link extra OAuth scopes or accounts to an existing user |
| **Security** | Signed double-submit CSRF, `__Host-` / `__Secure-` cookies, cross-subdomain SSO, PBKDF2-SHA256 |

---

## Installation

```toml
[dependencies]
authrust = "0.1"
```

The `axum` feature is **enabled by default** and adds `Authorization::handler()` (returns an `axum::Router`). Disable it when you are not using axum:

```toml
authrust = { version = "0.1", default-features = false }
```

---

## Quick start

```rust,no_run
use std::sync::Arc;
use authrust::{Authorization, Config, JsonbArray, User, providers::google};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::PgPool::connect("postgres://localhost/app").await?;

    let auth = Authorization::new(Config {
        jwt_secret: "change-me".into(),            // required — HMAC signing secret
        auth_url: "https://app.example.com".into(), // external base URL
        db: Some(pool),                            // required (users + sessions)
        providers: vec![google::new("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")],
        // Map the provider profile onto a user in YOUR database.
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
        .merge(auth.handler()) // all auth endpoints
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

Expected database schema: [`examples/schema.sql`](examples/schema.sql).

---

## HTTP endpoints

`auth.handler()` mounts routes under `authrust::DEFAULT_BASE_PATH` (`/api/authorization`):

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `GET` | `{base}/providers` | `get_providers` | JSON list of providers (Auth.js-compatible) |
| `ANY` | `{base}/provider/{provider}` | `handle_sign_in` | Start sign-in (OAuth redirect or credentials POST) |
| `ANY` | `{base}/provider/{provider}/callback` | `handle_callback` | OAuth/OIDC callback → session + callback page |

You can also register the three handlers yourself, or use `auth.route(request)` as a catch-all dispatcher (see the [actix-web example](examples/actix/README.md)).

### Sign-in options

| Query / header | Effect |
|----------------|--------|
| `?json=true` · `X-Auth-Return-Redirect: 1` · `Accept: application/json` | Return the authorization URL as JSON instead of a 302 |
| `?flow=token` · `X-Auth-Flow: token` | Token flow for mobile / API clients |
| `?connect=1&resource_id=<uuid>` | **Connect** flow — link OAuth account/scopes to an existing user; runs `Config::on_provider_connect` when done |

---

## Middlewares

All middlewares are `tower` layers:

```rust,no_run
# use authrust::Authorization;
# fn demo(auth: &Authorization) {
// Bearer JWT (Authorization header or ?access_token=) for APIs
auth.use_api_authorization([
    auth.with_roles(["admin"]),                // optional role gate
    auth.with_excluded_paths(["/api/public"]), // optional path prefixes to skip
]);

// Session cookie for server-rendered pages
// Unauthenticated → redirect to Config::sign_in_redirect_url?redirectUrl=<original>
auth.use_web_authorization([]);

// Refresh-token endpoint: only active when the client sends the opt-in header
// (authrust::REFRESH_TOKEN_HANDLER_IDENTIFIER, "cft"); otherwise passes through
auth.handle_refresh_token();
# }
```

### Reading auth data in a handler

```rust,no_run
# use authrust::{Authorization, http::RequestContext};
# async fn demo(auth: &Authorization, parts: &http::request::Parts) {
let r = RequestContext::new(parts);

let claims = auth.get_claims(&r);            // validated token claims
let roles = auth.get_roles(&r);              // Vec<String> from the "roles" claim
let data = auth.get_auth_data_api(&r);       // AuthData { session_id, user_id, roles }
let data = auth.get_auth_data_web(&r).await; // same, from the session cookie
# }
```

---

## Configuration

```rust,no_run
# use std::time::Duration;
# use authrust::{Config, CookieOptions};
Config {
    // Required
    jwt_secret: "...".into(),                // HMAC signing secret
    auth_url: "https://...".into(),          // external origin (falls back to request headers)
    db: None,                                // Option<sqlx::PgPool> — required at runtime

    // Tokens
    signing_method: "HS256".into(),          // HS256 | HS384 | HS512
    access_token_duration: "60s".into(),     // s / m / h / d / w / mo / y
    refresh_token_duration: "1y".into(),

    // Web
    sign_in_redirect_url: "/sign-in".into(),
    cookie_session_name: "cnf.id".into(),
    cookies: CookieOptions::default(),

    // Storage
    redis: None,                             // optional session cache
    redis_prefix: "AUTHSESSIONS".into(),
    redis_ttl: Duration::from_secs(30 * 60),
    user_table_name: "users".into(),         // needs at least: id, roles
    session_table_name: "sessions".into(),   // see examples/schema.sql

    // Providers & callbacks
    providers: vec![],
    resolve_user: None,                      // required for OAuth sign-in
    on_provider_connect: None,
};
```

### Cross-subdomain SSO

Share sessions across `example.com`, `admin.example.com`, etc. All apps must use the same `jwt_secret`:

```rust,no_run
let cookies = authrust::cross_subdomain_cookies(".example.com");
// Config { cookies, .. }
```

---

## Tokens, sessions & roles

| API | Purpose |
|-----|---------|
| `auth.authorize(opts)` | Create a session and sign an access/refresh pair (OAuth callback does this; call it yourself for custom flows such as LDAP) |
| `auth.check_session(&mut w, &r)` | Validate refresh token, refresh access token with up-to-date roles, re-set session cookie |
| `auth.get_role(endpoint_roles, user_roles)` | Check `name:perms` grants (`r` / `w` / `rw`) → `(has_role, can_read, can_write)` |
| `hash_password` / `check_password` | PBKDF2-SHA256 (`$pbkdf2-sha256$...`) for credentials storage |

---

## Framework integration

authrust depends on **no** web framework. Examples are runnable workspace members:

| Framework | Example | Adapter |
|-----------|---------|---------|
| **axum** | [`examples/axum`](examples/axum/README.md) | None — `auth.handler()` is a `Router` |
| **actix-web** | [`examples/actix`](examples/actix/README.md) | Two small helpers (included in the example) |
| **hyper / tonic / any `tower` stack** | — | None |

How to run and test: [`examples/README.md`](examples/README.md).

---

## Providers

| Provider | Module | Notes | Docs |
|----------|--------|-------|------|
| Google | `providers::google` | OIDC — discovery, PKCE + state + nonce | [docs](docs/providers/google.md) |
| Azure AD / Entra ID | `providers::azuread` | OIDC v2.0 + Microsoft Graph profile | [docs](docs/providers/azuread.md) |
| Credentials | `providers::credentials` | Username/password with a custom `authorize` callback | [docs](docs/providers/credentials.md) |
| LDAP / Active Directory | `providers::ldap` | Directory bind + attribute and role mapping | [docs](docs/providers/ldap.md) |

Overview and custom providers: [`docs/providers/README.md`](docs/providers/README.md).

Any other OAuth/OIDC service works as a plain `OAuthProvider`. The `Provider` trait is public if you need a custom one.

---

## Releasing

Releases are automated with [release-plz](https://release-plz.dev) (same pattern used across the Rust ecosystem).

| Conventional commit | SemVer bump |
|---------------------|-------------|
| `fix: …` | **patch** — `0.1.0` → `0.1.1` |
| `feat: …` | **minor** — `0.1.0` → `0.2.0` |
| `feat!: …` or `BREAKING CHANGE:` | **major** — `0.1.0` → `1.0.0` |

1. Merge work to `main` with conventional commits.
2. GitHub Actions opens/updates a release PR (`Cargo.toml` + [`CHANGELOG.md`](CHANGELOG.md)).
3. Merge that PR → tag `vX.Y.Z`, GitHub Release, and `cargo publish` to crates.io.

One-time setup: allow Actions to create PRs, and add the `CARGO_REGISTRY_TOKEN` repository secret (crates.io API token).

---

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

Copyright (c) 2026 [Izet Molla](https://github.com/izetmolla)
