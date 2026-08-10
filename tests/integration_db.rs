//! Integration tests against real PostgreSQL and Redis from `.env`.
//!
//! Required environment variables (loaded from `.env` when present):
//! - `DATABASE_URL` — Postgres connection string
//! - `REDIS_URL` — Redis connection string
//!
//! Run with:
//! ```bash
//! cargo test --test integration_db -- --nocapture
//! ```

use std::time::Duration;

use authrust::{
    Authorization, Config, JsonbArray, RequestContext, ResponseWriter, Tokens, build_redis_key,
    deserialize_session_data,
};
use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use redis::AsyncCommands;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

const TEST_USER_ID: &str = "00000000-0000-0000-0000-000000000001";
const JWT_SECRET: &str = "authrust-integration-test-secret";

static ENV: OnceCell<()> = OnceCell::const_new();
static SCHEMA: OnceCell<()> = OnceCell::const_new();

async fn load_env() {
    ENV.get_or_init(|| async {
        let _ = dotenvy::dotenv();
    })
    .await;
}

async fn database_url() -> String {
    load_env().await;
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set (see .env.example)")
}

async fn redis_url() -> String {
    load_env().await;
    std::env::var("REDIS_URL").expect("REDIS_URL must be set (see .env.example)")
}

async fn connect_pool() -> PgPool {
    PgPool::connect(&database_url().await)
        .await
        .expect("connect to DATABASE_URL")
}

async fn ensure_schema(pool: &PgPool) {
    SCHEMA
        .get_or_init(|| async {
            // Apply statements one-by-one so concurrent test processes (or a
            // race on CREATE EXTENSION) cannot abort the whole script.
            let statements = [
                r#"CREATE EXTENSION IF NOT EXISTS "pgcrypto""#,
                r#"CREATE TABLE IF NOT EXISTS users (
                    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                    roles   jsonb NOT NULL DEFAULT '[]'::jsonb,
                    content jsonb NOT NULL DEFAULT '{}'::jsonb
                )"#,
                r#"CREATE TABLE IF NOT EXISTS sessions (
                    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id    uuid REFERENCES users (id) ON DELETE CASCADE,
                    "type"     text NOT NULL DEFAULT 'sign_in',
                    ip_address text,
                    user_agent text,
                    method     text NOT NULL DEFAULT 'credentials',
                    account    jsonb,
                    expires_at timestamptz,
                    is_deleted boolean NOT NULL DEFAULT false,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    deleted_at timestamptz
                )"#,
                r#"CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id)"#,
                r#"INSERT INTO users (id, roles)
                   VALUES ('00000000-0000-0000-0000-000000000001', '["admin:rw"]'::jsonb)
                   ON CONFLICT (id) DO NOTHING"#,
            ];

            let pool = pool.clone();
            for sql in statements {
                if let Err(err) = sqlx::query(sql).execute(&pool).await {
                    // Concurrent CREATE EXTENSION IF NOT EXISTS can still race
                    // with error 23505 on pg_extension; ignore that case.
                    let message = err.to_string();
                    if !(message.contains("23505") && message.contains("pgcrypto")) {
                        panic!("apply schema statement failed: {err}\nSQL: {sql}");
                    }
                }
            }
        })
        .await;
}

async fn build_auth(pool: PgPool) -> Authorization {
    let redis = redis::Client::open(redis_url().await).expect("parse REDIS_URL");
    Authorization::new(Config {
        jwt_secret: JWT_SECRET.into(),
        auth_url: "http://localhost:3000".into(),
        db: Some(pool),
        redis: Some(redis),
        redis_prefix: format!("AUTHTEST:{}", Uuid::new_v4()),
        redis_ttl: Duration::from_secs(60),
        ..Config::default()
    })
    .expect("Authorization::new")
}

async fn delete_session(pool: &PgPool, session_id: &str) {
    sqlx::query("DELETE FROM sessions WHERE id = $1::uuid")
        .bind(session_id)
        .execute(pool)
        .await
        .expect("delete test session");
}

#[tokio::test]
async fn postgres_and_redis_are_reachable() {
    let pool = connect_pool().await;
    ensure_schema(&pool).await;

    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("SELECT 1");
    assert_eq!(one, 1);

    let client = redis::Client::open(redis_url().await).expect("parse REDIS_URL");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to REDIS_URL");
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .expect("PING");
    assert_eq!(pong, "PONG");
}

#[tokio::test]
async fn authorize_persists_session_in_postgres() {
    let pool = connect_pool().await;
    ensure_schema(&pool).await;
    let auth = build_auth(pool.clone()).await;

    let (tokens, session_id) = auth
        .authorize([
            auth.with_user_id(TEST_USER_ID),
            auth.with_user_roles(JsonbArray::from_iter(["admin:rw"])),
            auth.with_ip_address("127.0.0.1"),
            auth.with_user_agent("authrust-integration"),
            auth.with_method("credentials"),
        ])
        .await
        .expect("authorize");

    assert!(!session_id.is_empty());
    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());

    let session = auth.get_session(&session_id).await.expect("get_session");
    assert_eq!(session.id, session_id);
    assert_eq!(session.user_id, TEST_USER_ID);
    assert_eq!(session.user.id, TEST_USER_ID);
    assert!(
        session
            .user
            .roles
            .iter()
            .any(|role| role.as_str() == Some("admin:rw")),
        "roles should include admin:rw from the users table"
    );

    delete_session(&pool, &session_id).await;
}

#[tokio::test]
async fn session_is_cached_in_redis_and_reloaded() {
    let pool = connect_pool().await;
    ensure_schema(&pool).await;
    let auth = build_auth(pool.clone()).await;

    let (_tokens, session_id) = auth
        .authorize([
            auth.with_user_id(TEST_USER_ID),
            auth.with_method("credentials"),
        ])
        .await
        .expect("authorize");

    // First load warms Redis from Postgres.
    let session = auth.get_session(&session_id).await.expect("get_session");
    assert_eq!(session.id, session_id);

    let cached = auth
        .get_session_from_redis(&session_id)
        .await
        .expect("get_session_from_redis");
    assert_eq!(cached.id, session_id);
    assert_eq!(cached.user_id, TEST_USER_ID);

    let redis_key = build_redis_key(auth.redis_prefix(), &session_id);
    let client = auth.redis().expect("redis configured").clone();
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let raw: String = conn.get(&redis_key).await.expect("GET session key");
    let parsed = deserialize_session_data(&raw).expect("deserialize SessionData");
    assert_eq!(parsed.id, session_id);

    delete_session(&pool, &session_id).await;
    let _: () = conn.del(&redis_key).await.expect("DEL session key");
}

#[tokio::test]
async fn check_session_refreshes_access_token() {
    let pool = connect_pool().await;
    ensure_schema(&pool).await;
    let auth = build_auth(pool.clone()).await;

    let (
        Tokens {
            access_token: _,
            refresh_token,
        },
        session_id,
    ) = auth
        .authorize([
            auth.with_user_id(TEST_USER_ID),
            auth.with_method("credentials"),
        ])
        .await
        .expect("authorize");

    let body = Full::new(Bytes::from(
        json!({ "refresh_token": refresh_token }).to_string(),
    ));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/refresh")
        .header("content-type", "application/json")
        .body(body)
        .expect("build request");
    let (parts, body) = request.into_parts();
    let collected = BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    let r = RequestContext::with_body(&parts, collected);
    let mut w = ResponseWriter::new();

    let result = auth
        .check_session(&mut w, &r)
        .await
        .expect("check_session");
    assert_eq!(result.session_id, session_id);
    assert!(!result.tokens.access_token.is_empty());
    assert_eq!(result.user_id, TEST_USER_ID);

    delete_session(&pool, &session_id).await;
}

#[tokio::test]
async fn get_user_roles_from_db_reads_seeded_user() {
    let pool = connect_pool().await;
    ensure_schema(&pool).await;
    let auth = build_auth(pool).await;

    let roles = auth
        .get_user_roles_from_db(TEST_USER_ID)
        .await
        .expect("get_user_roles_from_db");
    assert!(
        roles.iter().any(|role| role.as_str() == Some("admin:rw")),
        "seeded demo user should have admin:rw"
    );
}
