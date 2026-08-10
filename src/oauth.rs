//! The OAuth 2.0 / OpenID Connect wire protocol: authorization URLs, code
//! exchange and userinfo lookups.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::checks::{pkce_challenge, provider_uses_check};
use crate::errors::{Error, Result};
use crate::provider::{Check, OAuthProvider};
use crate::types::{Profile, TokenSet, as_string};

/// Caps how much of a provider's HTTP response is read, so a misbehaving or
/// compromised endpoint cannot exhaust memory.
pub(crate) const MAX_RESPONSE_BYTES: usize = 1 << 20; // 1 MiB

/// The shared outbound HTTP client.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("default http client builds")
    })
}

/// The subset of an OpenID Connect discovery document this crate consumes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcConfig {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
}

/// Reads at most `limit` bytes of a response body.
pub(crate) async fn read_limited(mut response: reqwest::Response, limit: usize) -> Result<Bytes> {
    let mut buf = BytesMut::new();
    while let Some(chunk) = response.chunk().await? {
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(buf.freeze())
}

/// Builds the full authorization redirect URL including scope, state, and PKCE
/// challenge as applicable.
pub fn authorization_url(
    p: &OAuthProvider,
    callback_url: &str,
    state: &str,
    code_verifier: &str,
    nonce: &str,
) -> String {
    let endpoint = p.authorization_endpoint();
    if endpoint.is_empty() {
        return String::new();
    }

    // A sorted map reproduces Go's `url.Values.Encode`, which orders by key.
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    params.insert("client_id".into(), p.client_id.clone());
    params.insert("response_type".into(), "code".into());
    params.insert("redirect_uri".into(), callback_url.to_string());
    if !p.scopes.is_empty() {
        params.insert("scope".into(), p.scopes.join(" "));
    }
    if provider_uses_check(p, Check::State) && !state.is_empty() {
        params.insert("state".into(), state.to_string());
    }
    if provider_uses_check(p, Check::Pkce) && !code_verifier.is_empty() {
        params.insert("code_challenge".into(), pkce_challenge(code_verifier));
        params.insert("code_challenge_method".into(), "S256".into());
    }
    if provider_uses_check(p, Check::Nonce) && !nonce.is_empty() {
        params.insert("nonce".into(), nonce.to_string());
    }
    for (key, values) in &p.authorization_params {
        for value in values {
            params.insert(key.clone(), value.clone());
        }
    }

    let query = encode_form(&params);
    let separator = if endpoint.contains('?') { "&" } else { "?" };
    format!("{endpoint}{separator}{query}")
}

fn encode_form(params: &BTreeMap<String, String>) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

/// Swaps an authorization code for tokens at the token endpoint.
pub async fn exchange_code(
    p: &OAuthProvider,
    code: &str,
    callback_url: &str,
    code_verifier: &str,
) -> Result<TokenSet> {
    if code.is_empty() {
        return Err(Error::msg("authorization code is required"));
    }
    let token_url = p.token_endpoint();
    if token_url.is_empty() {
        return Err(Error::msg("provider missing token_url"));
    }

    let mut form: BTreeMap<String, String> = BTreeMap::new();
    form.insert("grant_type".into(), "authorization_code".into());
    form.insert("code".into(), code.to_string());
    form.insert("redirect_uri".into(), callback_url.to_string());
    if provider_uses_check(p, Check::Pkce) && !code_verifier.is_empty() {
        form.insert("code_verifier".into(), code_verifier.to_string());
    }

    let use_header = p.authorization_style == "header";
    if !use_header {
        form.insert("client_id".into(), p.client_id.clone());
        form.insert("client_secret".into(), p.client_secret.clone());
    }

    let mut request = http_client()
        .post(&token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(encode_form(&form));
    if use_header {
        let basic = BASE64_STANDARD.encode(format!("{}:{}", p.client_id, p.client_secret));
        request = request.header("Authorization", format!("Basic {basic}"));
    }

    let response = request
        .send()
        .await
        .map_err(|err| Error::msg(format!("token exchange: {err}")))?;

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = read_limited(response, MAX_RESPONSE_BYTES).await?;

    if !status.is_success() {
        return Err(Error::msg(format!(
            "token exchange: status {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        )));
    }

    parse_token_response(&body, &content_type)
}

/// Handles both JSON and (legacy) form-encoded token bodies, preserving every
/// field in [`TokenSet::raw`].
pub fn parse_token_response(body: &[u8], content_type: &str) -> Result<TokenSet> {
    let raw: JsonMap<String, Value> =
        if content_type.contains("application/json") || body.first() == Some(&b'{') {
            serde_json::from_slice(body)
                .map_err(|err| Error::msg(format!("token exchange: decode json: {err}")))?
        } else {
            let text = std::str::from_utf8(body)
                .map_err(|err| Error::msg(format!("token exchange: decode form: {err}")))?;
            form_urlencoded::parse(text.as_bytes())
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect()
        };

    let mut tokens = TokenSet {
        access_token: as_string(raw.get("access_token")),
        token_type: as_string(raw.get("token_type")),
        id_token: as_string(raw.get("id_token")),
        refresh_token: as_string(raw.get("refresh_token")),
        scope: as_string(raw.get("scope")),
        expires_in: 0,
        raw: JsonMap::new(),
    };
    if let Some(expires_in) = raw.get("expires_in").and_then(Value::as_i64) {
        tokens.expires_in = expires_in;
    }
    tokens.raw = raw;
    Ok(tokens)
}

/// Calls the userinfo endpoint with the access token.
pub async fn fetch_user_info(p: &OAuthProvider, tokens: &TokenSet) -> Result<Profile> {
    let user_info_url = p.user_info_endpoint();
    if user_info_url.is_empty() {
        // OIDC providers without a userinfo endpoint rely on the id_token; the
        // provider's profile function can parse it from the tokens.
        return Ok(Profile::new());
    }

    let response = http_client()
        .get(&user_info_url)
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| Error::msg(format!("userinfo: {err}")))?;

    let status = response.status();
    let body = read_limited(response, MAX_RESPONSE_BYTES).await?;
    if !status.is_success() {
        return Err(Error::msg(format!(
            "userinfo: status {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        )));
    }

    serde_json::from_slice(&body).map_err(|err| Error::msg(format!("userinfo: decode: {err}")))
}
