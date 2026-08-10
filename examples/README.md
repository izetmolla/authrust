# authrust examples

Each subdirectory is a runnable workspace member showing how to mount authrust on a specific web framework. They expose the same application, so you can diff them side by side — the only thing that changes is the adapter layer between `http`/`tower` and the framework.

| Example | Framework | README |
|---------|-----------|--------|
| [`axum/`](axum) | [axum 0.8](https://docs.rs/axum) | [axum/README.md](axum/README.md) |
| [`actix/`](actix) | [actix-web 4](https://actix.rs) | [actix/README.md](actix/README.md) |

## What every example implements

| Route | Protection | Shows |
|-------|-----------|-------|
| `ANY /api/authorization/*` | — | Mounting **all** authrust endpoints (`/providers`, `/provider/{id}`, `/provider/{id}/callback`) in one step |
| `POST /api/token/refresh` | — | Exchanging a refresh token for a fresh access token |
| `GET /api/profile` | Bearer JWT | Protecting a route and reading the principal via `auth.get_auth_data_api(&r)` |
| `GET /api/admin` (axum) / `GET /admin-api` (actix) | Bearer JWT + `admin` role | The role gate, and reading claims inside the handler |
| `GET /dashboard` | Session cookie | Unauthenticated requests are 307-redirected to `/sign-in?redirectUrl=...` |
| `GET /dashboard/public` | — | A path excluded from the cookie check |

## Setting up the database

authrust stores users and sessions in PostgreSQL. Create the schema once:

```bash
createdb authrust_example
psql authrust_example -f schema.sql
```

[`schema.sql`](schema.sql) also seeds the demo user (`00000000-0000-0000-0000-000000000001`, role `admin:rw`) that both examples' `resolve_user` returns.

## Running an example

```bash
cd examples/axum   # or examples/actix
DATABASE_URL=postgres://localhost/authrust_example cargo run
```

The server listens on `http://localhost:3000`. Both examples depend on authrust by path, so local changes are picked up immediately.

## Trying it out

List the configured providers:

```bash
curl http://localhost:3000/api/authorization/providers
```

Get the Google authorization URL as JSON (a real sign-in needs real client credentials in `main.rs`):

```bash
curl "http://localhost:3000/api/authorization/provider/google?json=true"
```

Hit a protected API route — expect `401` without a token:

```bash
curl -i http://localhost:3000/api/profile
```

Hit the cookie-protected page — expect a `307` redirect to the sign-in URL:

```bash
curl -i http://localhost:3000/dashboard
```

To test with a valid token end to end, configure real OAuth credentials and complete the sign-in flow in a browser; the callback page returns an access/refresh token pair and sets the session cookie. Then:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/api/profile
```

## Adapting to another framework

If your framework is built on `tower` (axum, tonic, warp via `tower::Service`), there is nothing to adapt: apply `auth.use_api_authorization(..)` and friends as layers.

Otherwise the recipe is the two functions at the bottom of the actix example:

1. Build an `http::request::Parts` from the framework's request, so `RequestContext` can read the method, URI, headers and cookies. Insert `ClientAddr` and `ConnectionSecure` extensions if you want peer-address and TLS detection.
2. Convert authrust's `http::Response<Full<Bytes>>` back into the framework's response type, copying **all** headers (a sign-in emits several `Set-Cookie` values).

With those in place, `auth.route(request)` serves the endpoints and the public helpers (`parse_jwt`, `get_role`, `get_auth_data_web`, `get_auth_redirect_url`) let you rebuild the guards in the framework's own middleware style.
