//! Mounting authrust on an axum application.
//!
//! authrust's middlewares are `tower` layers and its endpoints are plain
//! `http` handlers, so axum needs no adapter: `auth.handler()` returns a
//! `Router` and the layers go straight into `Router::layer`.
//!
//! Run with:
//!
//! ```text
//! createdb authrust_example
//! psql authrust_example -f ../schema.sql
//! DATABASE_URL=postgres://localhost/authrust_example cargo run
//! ```

use std::sync::Arc;

use authrust::http::RequestContext;
use authrust::providers::google;
use authrust::{Authorization, Config, JsonbArray, User};
use axum::Router;
use axum::extract::{Extension, Request};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::json;

/// The demo user every sign-in resolves to, seeded by `examples/schema.sql`.
const DEMO_USER_ID: &str = "00000000-0000-0000-0000-000000000001";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/authrust_example".to_string());
    let pool = sqlx::PgPool::connect(&database_url).await?;

    let auth = Authorization::new(Config {
        jwt_secret: "super-secret-change-me".into(),
        auth_url: "http://localhost:3000".into(),
        db: Some(pool),
        providers: vec![google::new("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")],
        // resolve_user maps the provider profile onto a user in your database.
        // A real implementation looks the profile up by email or provider id and
        // creates the row when it is missing.
        resolve_user: Some(Arc::new(|_profile| {
            Box::pin(async move {
                let user = User {
                    id: DEMO_USER_ID.to_string(),
                    roles: JsonbArray::from_iter(["admin:rw"]),
                    ..User::default()
                };
                Ok((Some(user), false))
            })
        })),
        ..Config::default()
    })?;

    // 1. Every authrust endpoint in one call:
    //
    //      GET {base}/providers
    //      ANY {base}/provider/{provider}
    //      ANY {base}/provider/{provider}/callback
    //
    //    where {base} is authrust::DEFAULT_BASE_PATH (/api/authorization).
    let app = Router::new()
        .merge(auth.handler())
        // 2. The refresh-token layer only activates when the client sends the
        //    opt-in "cft" header; otherwise the request falls through to the
        //    handler below.
        .route("/api/token/refresh", post(refresh_fallback))
        .layer(auth.handle_refresh_token())
        // 3. A route protected by the Bearer-JWT middleware. The principal is
        //    read back out of the request with get_auth_data_api.
        .merge(
            Router::new()
                .route("/api/profile", get(profile))
                .layer(auth.use_api_authorization([])),
        )
        // 4. The same middleware gated on a role. Claims validated by the
        //    middleware are on the request extensions.
        .merge(
            Router::new()
                .route("/api/admin", get(admin))
                .layer(auth.use_api_authorization([auth.with_roles(["admin"])])),
        )
        // 5. Cookie-based protection for server-rendered pages: unauthenticated
        //    requests are redirected to the sign-in URL.
        .merge(
            Router::new()
                .route("/dashboard", get(dashboard))
                .route("/dashboard/public", get(dashboard_public))
                .layer(
                    auth.use_web_authorization([auth.with_excluded_paths(["/dashboard/public"])]),
                ),
        )
        .layer(Extension(auth));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("listening on http://localhost:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn refresh_fallback() -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": "refresh header missing" })),
    )
}

async fn profile(Extension(auth): Extension<Authorization>, req: Request) -> impl IntoResponse {
    let (parts, _) = req.into_parts();
    let r = RequestContext::new(&parts);

    match auth.get_auth_data_api(&r) {
        Ok(data) => axum::Json(json!({
            "user_id": data.user_id,
            "session_id": data.session_id,
            "roles": data.roles,
        }))
        .into_response(),
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn admin(Extension(auth): Extension<Authorization>, req: Request) -> impl IntoResponse {
    let (parts, _) = req.into_parts();
    let r = RequestContext::new(&parts);

    let user_id = auth
        .get_claims(&r)
        .ok()
        .and_then(|claims| claims.get("user_id").cloned())
        .unwrap_or_default();

    axum::Json(json!({ "message": "hello, admin", "user_id": user_id }))
}

async fn dashboard() -> &'static str {
    "welcome to your dashboard"
}

async fn dashboard_public() -> &'static str {
    "anyone can read this"
}
