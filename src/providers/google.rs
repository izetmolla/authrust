//! Google sign-in via OpenID Connect discovery.
//!
//! ```no_run
//! use authrust::providers::google;
//!
//! let provider = google::new("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET");
//! ```

use std::sync::Arc;

use crate::provider::{Check, OAuthProvider, Provider, ProviderType};
use crate::providers::common;
use crate::user::OAuthUser;

/// Returns a configured Google provider using OpenID Connect discovery.
pub fn new(client_id: &str, client_secret: &str) -> Arc<dyn Provider> {
    Arc::new(OAuthProvider {
        provider_id: "google".to_string(),
        display_name: "Google".to_string(),
        kind: Some(ProviderType::Oidc),
        issuer: "https://accounts.google.com".to_string(),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        scopes: vec!["openid".into(), "email".into(), "profile".into()],
        checks: vec![Check::Pkce, Check::State, Check::Nonce],
        profile: Some(Arc::new(|p, _tokens| {
            Ok(OAuthUser {
                id: common::string(p.get("sub")),
                name: common::string(p.get("name")),
                email: common::string(p.get("email")),
                image: common::string(p.get("picture")),
                provider: "google".to_string(),
                ..OAuthUser::default()
            })
        })),
        ..OAuthProvider::default()
    })
}
