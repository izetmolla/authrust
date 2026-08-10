//! The provider model: OAuth/OIDC services and credentials forms.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use crate::authorization::Authorization;
use crate::errors::Result;
use crate::oauth::OidcConfig;
use crate::types::{Profile, TokenSet};
use crate::user::OAuthUser;

/// A `url.Values`-shaped multimap of authorization request parameters.
pub type UrlValues = HashMap<String, Vec<String>>;

/// Maps the raw provider profile (and tokens) into a user.
pub type ProfileFn = Arc<dyn Fn(&Profile, &TokenSet) -> Result<OAuthUser> + Send + Sync>;

/// Validates credentials and returns the signed-in user, or `None` to reject.
pub type CredentialsAuthorizeFn = Arc<
    dyn Fn(
            HashMap<String, String>,
            CredentialsRequest,
        ) -> BoxFuture<'static, Result<Option<OAuthUser>>>
        + Send
        + Sync,
>;

/// Enumerates the kinds of providers, mirroring Auth.js.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    OAuth,
    Oidc,
    Email,
    Credentials,
    Passkey,
}

impl ProviderType {
    /// The wire representation used in JSON payloads and session rows.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::OAuth => "oauth",
            ProviderType::Oidc => "oidc",
            ProviderType::Email => "email",
            ProviderType::Credentials => "credentials",
            ProviderType::Passkey => "passkey",
        }
    }
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An OAuth security check performed during the authorization flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Check {
    Pkce,
    State,
    Nonce,
}

/// The JSON shape returned by the `/providers` endpoint, matching Auth.js so
/// existing client SDKs can consume it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicProvider {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "signinUrl")]
    pub sign_in_url: String,
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
}

/// The common interface implemented by every provider.
pub trait Provider: Send + Sync + 'static {
    /// The unique, URL-safe identifier used in routes (e.g. `github`).
    fn id(&self) -> &str;
    /// The human-readable display name (e.g. `GitHub`).
    fn name(&self) -> &str;
    /// Categorizes the provider.
    fn type_(&self) -> ProviderType;

    /// Downcasts to an OAuth provider. Replaces Go's type switch.
    fn as_oauth(&self) -> Option<&OAuthProvider> {
        None
    }

    /// Downcasts to a credentials provider. Replaces Go's type switch.
    fn as_credentials(&self) -> Option<&CredentialsProvider> {
        None
    }
}

/// Describes an OAuth 2.0 or OpenID Connect provider. Endpoints can be
/// specified explicitly or discovered from an OIDC issuer.
#[derive(Default)]
pub struct OAuthProvider {
    pub provider_id: String,
    pub display_name: String,
    /// [`ProviderType::OAuth`] or [`ProviderType::Oidc`]; defaults to the former.
    pub kind: Option<ProviderType>,
    pub client_id: String,
    pub client_secret: String,

    /// Enables OIDC discovery of the authorization, token and userinfo URLs.
    pub issuer: String,

    pub authorization_url: String,
    pub authorization_params: UrlValues,
    pub token_url: String,
    pub user_info_url: String,

    pub scopes: Vec<String>,
    pub checks: Vec<Check>,

    /// Maps the raw provider profile into a user. Required.
    pub profile: Option<ProfileFn>,

    /// Controls how client credentials are sent to the token endpoint: `body`
    /// (default) or `header` (HTTP Basic).
    pub authorization_style: String,

    /// Cache for the OIDC discovery document. Leave at its default; it is
    /// populated by [`crate::provider_utils::discover`].
    pub discovered: OnceCell<OidcConfig>,
}

impl fmt::Debug for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthProvider")
            .field("provider_id", &self.provider_id)
            .field("display_name", &self.display_name)
            .field("kind", &self.kind)
            .field("issuer", &self.issuer)
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("user_info_url", &self.user_info_url)
            .field("scopes", &self.scopes)
            .field("checks", &self.checks)
            .field("authorization_style", &self.authorization_style)
            .finish()
    }
}

impl OAuthProvider {
    /// The effective authorization endpoint: the configured value, or the one
    /// found by OIDC discovery.
    pub fn authorization_endpoint(&self) -> String {
        self.endpoint(&self.authorization_url, |cfg| &cfg.authorization_endpoint)
    }

    /// The effective token endpoint.
    pub fn token_endpoint(&self) -> String {
        self.endpoint(&self.token_url, |cfg| &cfg.token_endpoint)
    }

    /// The effective userinfo endpoint.
    pub fn user_info_endpoint(&self) -> String {
        self.endpoint(&self.user_info_url, |cfg| &cfg.userinfo_endpoint)
    }

    fn endpoint(&self, configured: &str, pick: impl Fn(&OidcConfig) -> &String) -> String {
        if !configured.is_empty() {
            return configured.to_string();
        }
        self.discovered
            .get()
            .map(|cfg| pick(cfg).clone())
            .unwrap_or_default()
    }
}

impl Provider for OAuthProvider {
    fn id(&self) -> &str {
        &self.provider_id
    }

    fn name(&self) -> &str {
        &self.display_name
    }

    fn type_(&self) -> ProviderType {
        self.kind.unwrap_or(ProviderType::OAuth)
    }

    fn as_oauth(&self) -> Option<&OAuthProvider> {
        Some(self)
    }
}

/// Describes a single input of a credentials form, mirroring the Auth.js
/// `credentials` map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialField {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub placeholder: String,
}

/// The parts of the incoming request handed to a credentials `authorize`
/// callback. Go passes the whole `*http.Request`; the callback runs in a
/// `'static` future here, so the relevant pieces are copied instead.
#[derive(Debug, Clone)]
pub struct CredentialsRequest {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub remote_addr: Option<SocketAddr>,
}

/// Authenticates with arbitrary credentials via a user-supplied `authorize`
/// function. Sessions for credentials providers always use the JWT strategy,
/// exactly as in Auth.js.
#[derive(Default)]
pub struct CredentialsProvider {
    pub provider_id: String,
    pub display_name: String,
    pub fields: Vec<CredentialField>,
    /// Validates credentials and returns the signed-in user, or `None` to
    /// reject with a generic invalid-credentials response.
    pub authorize: Option<CredentialsAuthorizeFn>,
}

impl fmt::Debug for CredentialsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialsProvider")
            .field("provider_id", &self.provider_id)
            .field("display_name", &self.display_name)
            .field("fields", &self.fields)
            .field("authorize", &self.authorize.is_some())
            .finish()
    }
}

impl Provider for CredentialsProvider {
    fn id(&self) -> &str {
        &self.provider_id
    }

    fn name(&self) -> &str {
        &self.display_name
    }

    fn type_(&self) -> ProviderType {
        ProviderType::Credentials
    }

    fn as_credentials(&self) -> Option<&CredentialsProvider> {
        Some(self)
    }
}

impl Authorization {
    /// Returns the configured provider with the given id.
    pub fn find_provider(&self, id: &str) -> Option<&Arc<dyn Provider>> {
        self.providers().iter().find(|p| p.id() == id)
    }
}
