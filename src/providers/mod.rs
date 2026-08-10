//! Built-in identity provider presets.
//!
//! Each preset returns an `Arc<dyn Provider>` ready for
//! [`Config::providers`](crate::Config::providers):
//!
//! | Module | Provider |
//! |--------|----------|
//! | [`google`] | Google OIDC |
//! | [`azuread`] | Azure AD / Entra ID |
//! | [`credentials`] | Username / password |
//! | [`ldap`] | LDAP / Active Directory |
//!
//! Any other OAuth/OIDC service can use a plain
//! [`OAuthProvider`](crate::OAuthProvider). The [`Provider`](crate::Provider)
//! trait is public for custom implementations.

pub mod azuread;
pub mod common;
pub mod credentials;
pub mod google;
pub mod ldap;
