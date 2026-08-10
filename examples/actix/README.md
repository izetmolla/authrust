# authrust + actix-web

actix-web is not built on `tower`, so authrust's layers cannot be applied directly. Everything below the layers is framework-agnostic, and this example bridges the gap with two functions plus three guards written in actix's own middleware style.

## Running

```bash
createdb authrust_example
psql authrust_example -f ../schema.sql
DATABASE_URL=postgres://localhost/authrust_example cargo run
```

The server listens on `http://localhost:3000`.

## The adapters

`request_parts` rebuilds the `http::request::Parts` that `RequestContext` reads, carrying over the method, URI, headers, peer address and TLS state:

```rust
fn request_parts(req: &HttpRequest) -> http::request::Parts
```

`into_actix` converts an authrust response back, copying every header so that the multiple `Set-Cookie` values a sign-in emits all survive:

```rust
async fn into_actix(response: authrust::Response) -> HttpResponse
```

## Mounting the endpoints

actix has no `merge`, so the endpoints go behind one catch-all route and `auth.route()` dispatches:

```rust
web::resource(format!("{DEFAULT_BASE_PATH}/{{tail:.*}}")).to(authorization_endpoints)
```

## The guards

`api_auth`, `admin_auth` and `web_auth` are `actix_web::middleware::from_fn` middlewares that reimplement `ApiAuthorizationLayer` and `WebAuthorizationLayer` on top of the same public helpers:

| Guard | Uses | Equivalent layer |
|-------|------|------------------|
| `api_auth` | `extract_bearer_token`, `parse_jwt` | `auth.use_api_authorization([])` |
| `admin_auth` | the above plus `roles_from_any`, `get_role` | `auth.use_api_authorization([auth.with_roles(["admin"])])` |
| `web_auth` | `get_auth_data_web`, `get_auth_redirect_url` | `auth.use_web_authorization([])` |

Each guard puts the validated `JwtToken` on the actix request extensions; `request_parts_with_claims` copies it into the `Parts` it builds so `get_claims` and `get_auth_data_api` find it in the handler.

Excluded paths are expressed by registering the route outside the guarded scope rather than through `with_excluded_paths`.

## Notes

- The example depends on authrust with `default-features = false`, since the `axum` feature is not needed here.
- `refresh_token` uses `auth.check_session`, the direct equivalent of what `RefreshTokenLayer` does once a client has opted in with the `cft` header.
