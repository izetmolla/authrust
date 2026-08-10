//! Provider presets.
//!
//! Every preset returns an `Arc<dyn Provider>` ready to drop into
//! [`Config::providers`](crate::authorization::Config::providers). Any other
//! OAuth/OIDC service can be configured with a plain
//! [`OAuthProvider`](crate::provider::OAuthProvider).

pub mod azuread;
pub mod common;
pub mod credentials;
pub mod google;
pub mod ldap;
