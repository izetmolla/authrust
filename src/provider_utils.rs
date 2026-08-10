//! Origin resolution, callback parameter merging and OIDC discovery.

use std::collections::HashMap;

use url::Url;

use crate::authorization::Authorization;
use crate::errors::{Error, Result};
use crate::http::{RequestContext, is_secure_request};
use crate::oauth::{MAX_RESPONSE_BYTES, OidcConfig, http_client, read_limited};
use crate::provider::OAuthProvider;

impl Authorization {
    /// Resolves the external base URL and whether it is HTTPS, honouring
    /// `Config::auth_url` and falling back to request headers when it is unset.
    pub fn origin(&self, r: &RequestContext<'_>) -> Result<(String, bool)> {
        if !self.auth_url().is_empty() {
            return parse_origin_url(self.auth_url());
        }
        let is_secure = is_secure_request(r);
        let scheme = if is_secure { "https" } else { "http" };
        let forwarded = r.header("x-forwarded-host");
        let host = if forwarded.is_empty() {
            r.host()
        } else {
            forwarded
        };
        Ok((format!("{scheme}://{host}"), is_secure))
    }

    /// Builds the provider callback URL for the current request.
    pub fn callback_url(&self, origin: &str, provider_id: &str) -> String {
        format!(
            "{origin}{}/provider/{provider_id}/callback",
            crate::constants::DEFAULT_BASE_PATH
        )
    }

    /// Builds the provider sign-in URL for the current request.
    pub fn sign_in_url(&self, origin: &str, provider_id: &str) -> String {
        format!(
            "{origin}{}/provider/{provider_id}",
            crate::constants::DEFAULT_BASE_PATH
        )
    }
}

/// Normalizes a configured `auth_url` into an absolute base URL. Values without
/// a scheme default to `https://` so OAuth `redirect_uri` values stay valid.
pub fn parse_origin_url(raw: &str) -> Result<(String, bool)> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.is_empty() {
        return Ok((String::new(), false));
    }
    let raw = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&raw).map_err(|err| Error::config(format!("invalid auth_url: {err}")))?;
    let Some(host) = url.host_str() else {
        return Err(Error::config(format!("invalid auth_url: {raw:?}")));
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let scheme = url.scheme();
    Ok((format!("{scheme}://{authority}"), scheme == "https"))
}

/// Returns the OAuth callback parameters from the query string, merging POST
/// form fields for providers that use `response_mode=form_post` (e.g. Sign in
/// with Apple).
pub fn callback_query(r: &RequestContext<'_>) -> HashMap<String, String> {
    let mut merged: HashMap<String, String> = HashMap::new();
    for (key, values) in r.query() {
        if let Some(first) = values.first() {
            merged.insert(key.clone(), first.clone());
        }
    }
    if r.method() == http::Method::POST {
        for (key, values) in r.post_form() {
            let Some(first) = values.first() else {
                continue;
            };
            if first.is_empty() {
                continue;
            }
            if merged.get(key).is_some_and(|value| !value.is_empty()) {
                continue;
            }
            merged.insert(key.clone(), first.clone());
        }
    }
    merged
}

/// Fills in any missing OAuth endpoints from the provider's OIDC issuer.
///
/// It is a no-op when the endpoints are already set or no issuer is configured.
/// The fetched document is cached on the provider, so repeated sign-ins do not
/// re-request it.
pub async fn discover(p: &OAuthProvider) -> Result<()> {
    if p.issuer.is_empty() {
        return Ok(());
    }
    if !p.authorization_url.is_empty() && !p.token_url.is_empty() {
        return Ok(());
    }
    p.discovered
        .get_or_try_init(|| fetch_oidc_config(&p.issuer))
        .await?;
    Ok(())
}

async fn fetch_oidc_config(issuer: &str) -> Result<OidcConfig> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let response = http_client()
        .get(&well_known)
        .send()
        .await
        .map_err(|err| Error::msg(format!("oidc discovery: {err}")))?;

    let status = response.status();
    if status.as_u16() != 200 {
        return Err(Error::msg(format!(
            "oidc discovery: unexpected status {}",
            status.as_u16()
        )));
    }
    let body = read_limited(response, MAX_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|err| Error::msg(format!("oidc discovery: decode: {err}")))
}
