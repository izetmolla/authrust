//! Username/password (or any custom fields) sign-in.
//!
//! ```no_run
//! use std::sync::Arc;
//! use authrust::providers::credentials;
//! use authrust::user::OAuthUser;
//!
//! let provider = credentials::new(credentials::Options {
//!     authorize: Some(Arc::new(|creds, _req| {
//!         Box::pin(async move {
//!             let username = creds.get("username").cloned().unwrap_or_default();
//!             Ok(Some(OAuthUser { id: username, ..Default::default() }))
//!         })
//!     })),
//!     ..Default::default()
//! });
//! ```

use std::sync::Arc;

use crate::provider::{CredentialField, CredentialsAuthorizeFn, CredentialsProvider, Provider};

/// Configures a credentials provider.
#[derive(Default)]
pub struct Options {
    /// Defaults to `credentials`.
    pub id: String,
    /// Defaults to `Credentials`.
    pub name: String,
    /// The form fields presented to the client.
    pub fields: Vec<CredentialField>,
    /// Validates the submitted credentials. Required for sign-in to succeed.
    pub authorize: Option<CredentialsAuthorizeFn>,
}

/// Builds a credentials provider. Credentials sessions always use the JWT
/// strategy.
pub fn new(o: Options) -> Arc<dyn Provider> {
    let id = if o.id.is_empty() {
        "credentials".to_string()
    } else {
        o.id
    };
    let name = if o.name.is_empty() {
        "Credentials".to_string()
    } else {
        o.name
    };
    Arc::new(CredentialsProvider {
        provider_id: id,
        display_name: name,
        fields: o.fields,
        authorize: o.authorize,
    })
}
