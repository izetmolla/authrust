//! Mounting authrust on an actix-web application.
//!
//! actix-web is not built on `tower`, so its middlewares cannot be used
//! directly. Everything below the layers is still framework-agnostic, and this
//! example wires it up with two small adapters:
//!
//! - [`request_parts`] turns an `actix_web::HttpRequest` into the
//!   `http::request::Parts` that [`RequestContext`] reads.
//! - [`into_actix`] turns an authrust response back into an `HttpResponse`.
//!
//! The guards below (`api_auth`, `admin_auth`, `web_auth`) reimplement what
//! `ApiAuthorizationLayer` and `WebAuthorizationLayer` do, using the same public
//! helpers.
//!
//! Run with:
//!
//! ```text
//! createdb authrust_example
//! psql authrust_example -f ../schema.sql
//! DATABASE_URL=postgres://localhost/authrust_example cargo run
//! ```

use std::sync::Arc;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::LOCATION;
use actix_web::middleware::{Next, from_fn};
use actix_web::{App, Error, HttpMessage, HttpRequest, HttpResponse, HttpServer, web};
use http::request::Parts;
use http_body_util::BodyExt;
use authrust::claims::{JwtToken, jwt_from_context};
use authrust::constants::DEFAULT_BASE_PATH;
use authrust::http::{ClientAddr, ConnectionSecure, RequestContext};
use authrust::middleware::extract_bearer_token;
use authrust::providers::google;
use authrust::roles::roles_from_any;
use authrust::{Authorization, Config, JsonbArray, User};
use serde_json::json;

/// The demo user every sign-in resolves to, seeded by `examples/schema.sql`.
const DEMO_USER_ID: &str = "00000000-0000-0000-0000-000000000001";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/authrust_example".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect to postgres");

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
    })
    .expect("init authrust");

    println!("listening on http://localhost:3000");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(auth.clone()))
            // 1. Every authrust endpoint behind one catch-all route:
            //
            //      GET {base}/providers
            //      ANY {base}/provider/{provider}
            //      ANY {base}/provider/{provider}/callback
            .service(
                web::resource(format!("{DEFAULT_BASE_PATH}/{{tail:.*}}"))
                    .to(authorization_endpoints),
            )
            // 2. Refresh a expired access token from a refresh token.
            .route("/api/token/refresh", web::post().to(refresh_token))
            // 3. A route protected by the Bearer JWT, reading the principal back
            //    out of the request.
            .service(
                web::scope("/api")
                    .wrap(from_fn(api_auth))
                    .route("/profile", web::get().to(profile)),
            )
            // 4. The same check, gated on a role.
            .service(
                web::scope("/admin-api")
                    .wrap(from_fn(admin_auth))
                    .route("", web::get().to(admin)),
            )
            // 5. Cookie-based protection for server-rendered pages:
            //    unauthenticated requests are redirected to the sign-in URL.
            .service(
                web::scope("/dashboard")
                    .wrap(from_fn(web_auth))
                    .route("", web::get().to(dashboard)),
            )
            .route("/dashboard/public", web::get().to(dashboard_public))
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

// --- Handlers ---------------------------------------------------------------

async fn authorization_endpoints(
    auth: web::Data<Authorization>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let parts = request_parts(&req);
    let request = http::Request::from_parts(parts, http_body_util::Full::new(body));
    into_actix(auth.route(request).await).await
}

async fn refresh_token(
    auth: web::Data<Authorization>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let parts = request_parts(&req);
    let r = RequestContext::with_body(&parts, body);
    let mut w = authrust::ResponseWriter::new();

    match auth.check_session(&mut w, &r).await {
        Ok(result) => {
            let response = w.finish(authrust::response::write_json(
                http::StatusCode::OK,
                json!({
                    "tokens": result.tokens,
                    "session_id": result.session_id,
                    "user_id": result.user_id,
                }),
            ));
            into_actix(response).await
        }
        Err(err) => HttpResponse::Unauthorized().json(json!({ "error": err.to_string() })),
    }
}

async fn profile(auth: web::Data<Authorization>, req: HttpRequest) -> HttpResponse {
    let parts = request_parts_with_claims(&req);
    let r = RequestContext::new(&parts);

    match auth.get_auth_data_api(&r) {
        Ok(data) => HttpResponse::Ok().json(json!({
            "user_id": data.user_id,
            "session_id": data.session_id,
            "roles": data.roles,
        })),
        Err(err) => HttpResponse::Unauthorized().json(json!({ "error": err.to_string() })),
    }
}

async fn admin(req: HttpRequest) -> HttpResponse {
    let parts = request_parts_with_claims(&req);
    let user_id = jwt_from_context(&parts.extensions)
        .and_then(|token| token.claims.get("user_id").cloned())
        .unwrap_or_default();

    HttpResponse::Ok().json(json!({ "message": "hello, admin", "user_id": user_id }))
}

async fn dashboard() -> &'static str {
    "welcome to your dashboard"
}

async fn dashboard_public() -> &'static str {
    "anyone can read this"
}

// --- Guards -----------------------------------------------------------------

/// The equivalent of `auth.use_api_authorization([])`.
async fn api_auth<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    jwt_guard(req, next, &[]).await
}

/// The equivalent of `auth.use_api_authorization([auth.with_roles(["admin"])])`.
async fn admin_auth<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    jwt_guard(req, next, &["admin"]).await
}

async fn jwt_guard<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
    required_roles: &[&str],
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    let auth = authorization(&req);
    let parts = request_parts(req.request());
    let r = RequestContext::new(&parts);

    let token = match auth.parse_jwt(&extract_bearer_token(&r)) {
        Ok(token) => token,
        Err(err) => {
            let response = HttpResponse::Unauthorized()
                .json(json!({ "error": err.to_string(), "code": "UNAUTHORIZED" }));
            return Ok(req.into_response(response.map_into_right_body()));
        }
    };

    if !required_roles.is_empty() {
        let user_roles = token
            .claims
            .get("roles")
            .map(roles_from_any)
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default();
        let endpoint_roles: Vec<String> = required_roles.iter().map(|r| r.to_string()).collect();

        let (has_role, _, _) = auth.get_role(&endpoint_roles, &user_roles);
        if !has_role {
            let response = HttpResponse::Forbidden().json(json!({
                "error": format!("insufficient permissions: {}", endpoint_roles.join(", ")),
                "code": "INSUFFICIENT_PERMISSIONS",
            }));
            return Ok(req.into_response(response.map_into_right_body()));
        }
    }

    // Handlers read the validated token back through `request_parts_with_claims`.
    req.extensions_mut().insert(token);
    next.call(req)
        .await
        .map(ServiceResponse::map_into_left_body)
}

/// The equivalent of `auth.use_web_authorization([])`.
async fn web_auth<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error> {
    let auth = authorization(&req);
    let parts = request_parts(req.request());
    let r = RequestContext::new(&parts);

    if auth.get_auth_data_web(&r).await.is_ok() {
        return next
            .call(req)
            .await
            .map(ServiceResponse::map_into_left_body);
    }

    let response = HttpResponse::TemporaryRedirect()
        .insert_header((LOCATION, auth.get_auth_redirect_url(&r)))
        .finish();
    Ok(req.into_response(response.map_into_right_body()))
}

fn authorization(req: &ServiceRequest) -> Authorization {
    req.app_data::<web::Data<Authorization>>()
        .expect("Authorization registered as app data")
        .as_ref()
        .clone()
}

// --- Adapters ---------------------------------------------------------------

/// Rebuilds the `http` request head that [`RequestContext`] reads from.
fn request_parts(req: &HttpRequest) -> Parts {
    let mut builder = http::Request::builder()
        .method(req.method().as_str())
        .uri(req.uri().to_string());
    for (name, value) in req.headers() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    let mut request = builder.body(()).expect("request head is valid");
    if let Some(peer) = req.peer_addr() {
        request.extensions_mut().insert(ClientAddr(peer));
    }
    if req.connection_info().scheme() == "https" {
        request.extensions_mut().insert(ConnectionSecure(true));
    }
    request.into_parts().0
}

/// The same head, carrying the token a guard validated earlier so that
/// `get_auth_data_api` and `get_claims` can find it.
fn request_parts_with_claims(req: &HttpRequest) -> Parts {
    let mut parts = request_parts(req);
    if let Some(token) = req.extensions().get::<JwtToken>() {
        parts.extensions.insert(token.clone());
    }
    parts
}

/// Converts an authrust response into an actix one, preserving every header
/// (including the multiple `Set-Cookie` values a sign-in emits).
async fn into_actix(response: authrust::Response) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    let status = actix_web::http::StatusCode::from_u16(parts.status.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (name, value) in parts.headers.iter() {
        builder.append_header((name.as_str(), value.as_bytes()));
    }
    builder.body(bytes)
}
