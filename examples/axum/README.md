# authrust + axum

axum is built on `tower`, so authrust needs no adapter at all: `auth.handler()` **is** an `axum::Router`, and every middleware is a layer.

## Running

```bash
createdb authrust_example
psql authrust_example -f ../schema.sql
DATABASE_URL=postgres://localhost/authrust_example cargo run
```

The server listens on `http://localhost:3000`.

## How it is wired

Mount every auth endpoint:

```rust
let app = Router::new().merge(auth.handler());
```

Protect a group of routes. `Router::layer` applies to the routes added before it, so each protected group is its own `Router` that gets merged in:

```rust
Router::new()
    .route("/api/admin", get(admin))
    .layer(auth.use_api_authorization([auth.with_roles(["admin"])]))
```

Read the principal inside a handler. The middleware stores the validated token on the request extensions, and `RequestContext` is the view authrust's helpers read:

```rust
async fn profile(Extension(auth): Extension<Authorization>, req: Request) -> impl IntoResponse {
    let (parts, _) = req.into_parts();
    let r = RequestContext::new(&parts);
    let data = auth.get_auth_data_api(&r)?;
    // ...
}
```

The `Authorization` value is shared with handlers through `Extension`; `Extension` and `State` both work since cloning it is cheap.

## Notes

- `auth.handler()` requires the `axum` feature, which is on by default.
- Add `.layer(Extension(ClientAddr(addr)))` or serve with `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())` and copy `ConnectInfo` into a `ClientAddr` extension if you want the caller's IP recorded on session rows.
