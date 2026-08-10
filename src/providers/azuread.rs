//! Microsoft Azure Active Directory (Entra ID) sign-in via the v2.0 OAuth /
//! OIDC endpoints.
//!
//! ```no_run
//! use authrust::providers::azuread;
//!
//! let provider = azuread::new(azuread::Options {
//!     client_id: "YOUR_CLIENT_ID".into(),
//!     client_secret: "YOUR_CLIENT_SECRET".into(),
//!     tenant_id: "YOUR_TENANT_ID".into(),
//!     ..Default::default()
//! });
//! ```

use std::sync::Arc;

use crate::errors::Result;
use crate::provider::{Check, OAuthProvider, ProfileFn, Provider, ProviderType, UrlValues};
use crate::providers::common;
use crate::types::{Profile, TokenSet};
use crate::user::OAuthUser;

const AUTH_URL_TEMPLATE: &str = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize";
const TOKEN_URL_TEMPLATE: &str = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token";
const USER_INFO_URL: &str = "https://graph.microsoft.com/v1.0/me";

/// The provider id used in routes and session rows.
pub const PROVIDER_ID: &str = "azuread-v2";

/// The scopes requested when [`Options::scopes`] is empty.
pub fn default_scopes() -> Vec<String> {
    vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "User.Read".into(),
    ]
}

/// Configures the Azure AD provider.
#[derive(Default)]
pub struct Options {
    /// The Application (client) ID from the Azure portal.
    pub client_id: String,
    /// The client secret generated in the Azure portal.
    pub client_secret: String,
    /// Controls which accounts may sign in. Accepted values:
    ///
    /// - a tenant GUID: single-tenant (your organisation only)
    /// - `common`: any Azure AD or personal Microsoft account
    /// - `organizations`: any Azure AD account
    /// - `consumers`: personal Microsoft accounts only
    ///
    /// Defaults to `common` when empty.
    pub tenant_id: String,
    /// Overrides the default scope set. Set this to add or remove Microsoft
    /// Graph permissions.
    pub scopes: Vec<String>,
    /// Extra parameters appended to the OAuth authorize request.
    pub authorization_params: UrlValues,
    /// Optionally overrides the default user-mapping function.
    pub profile: Option<ProfileFn>,
}

/// Returns a configured Azure AD provider.
pub fn new(o: Options) -> Arc<dyn Provider> {
    let tenant = if o.tenant_id.is_empty() {
        "common".to_string()
    } else {
        o.tenant_id
    };
    let scopes = if o.scopes.is_empty() {
        default_scopes()
    } else {
        o.scopes
    };
    let profile = o
        .profile
        .unwrap_or_else(|| Arc::new(default_profile) as ProfileFn);

    Arc::new(OAuthProvider {
        provider_id: PROVIDER_ID.to_string(),
        display_name: "Azure Active Directory".to_string(),
        kind: Some(ProviderType::Oidc),
        issuer: format!("https://login.microsoftonline.com/{tenant}/v2.0"),
        client_id: o.client_id,
        client_secret: o.client_secret,
        authorization_url: AUTH_URL_TEMPLATE.replace("{tenant}", &tenant),
        token_url: TOKEN_URL_TEMPLATE.replace("{tenant}", &tenant),
        user_info_url: USER_INFO_URL.to_string(),
        scopes,
        authorization_params: o.authorization_params,
        checks: vec![Check::Pkce, Check::State, Check::Nonce],
        profile: Some(profile),
        ..OAuthProvider::default()
    })
}

/// Maps Azure AD / Microsoft Graph claims onto a user. It handles both OIDC
/// id_token claims and Graph API response fields.
pub fn default_profile(p: &Profile, _tokens: &TokenSet) -> Result<OAuthUser> {
    Ok(OAuthUser {
        id: common::first_non_empty([
            common::string(p.get("sub")),
            common::string(p.get("id")),
            common::string(p.get("oid")),
        ]),
        name: common::first_non_empty([
            common::string(p.get("name")),
            common::string(p.get("displayName")),
        ]),
        email: common::first_non_empty([
            common::string(p.get("email")),
            common::string(p.get("mail")),
            common::string(p.get("userPrincipalName")),
        ]),
        first_name: common::string(p.get("givenName")),
        last_name: common::string(p.get("surname")),
        image: common::string(p.get("picture")),
        provider: PROVIDER_ID.to_string(),
        ..OAuthUser::default()
    })
}
