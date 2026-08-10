//! Per-route middleware configuration.

use crate::authorization::Authorization;

/// Controls the per-route behaviour of the API and WEB middlewares.
///
/// Build it with [`new_auth_config_options`] plus the `with_*` options. The
/// default value is a valid no-op config: no excluded paths, no role gate.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub(crate) excluded_paths: Vec<String>,
    pub(crate) roles: Vec<String>,
}

impl AuthConfig {
    /// The path prefixes that skip authentication.
    pub fn excluded_paths(&self) -> &[String] {
        &self.excluded_paths
    }

    /// The role names gating the route.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
}

/// Mutates an [`AuthConfig`] in place.
pub type AuthConfigOptions = Box<dyn FnOnce(&mut AuthConfig) + Send>;

/// Applies the provided options on top of the defaults.
pub fn new_auth_config_options(opts: impl IntoIterator<Item = AuthConfigOptions>) -> AuthConfig {
    let mut cfg = AuthConfig::default();
    for opt in opts {
        opt(&mut cfg);
    }
    cfg
}

impl Authorization {
    /// Whitelists path prefixes that should not require auth.
    pub fn with_excluded_paths(
        &self,
        paths: impl IntoIterator<Item = impl Into<String>>,
    ) -> AuthConfigOptions {
        let paths: Vec<String> = paths.into_iter().map(Into::into).collect();
        Box::new(move |cfg: &mut AuthConfig| cfg.excluded_paths = paths)
    }

    /// Gates the route behind the given role names; the authenticated user must
    /// hold at least one of them.
    pub fn with_roles(
        &self,
        roles: impl IntoIterator<Item = impl Into<String>>,
    ) -> AuthConfigOptions {
        let roles: Vec<String> = roles.into_iter().map(Into::into).collect();
        Box::new(move |cfg: &mut AuthConfig| cfg.roles = roles)
    }
}
