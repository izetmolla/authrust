//! LDAP / Active Directory authentication.
//!
//! The client is standalone: use it inside a
//! [`credentials`](crate::providers::credentials) provider's `authorize`
//! callback to verify a username and password against a directory.

mod discover;
mod user;

use std::time::Duration;

use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions, ldap_escape,
};
use tokio::sync::OnceCell;

pub use discover::discover_base_dn;
pub use user::{User, first_non_empty};

use user::user_from_entry;

/// Errors returned by the LDAP client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ldap config: {0}")]
    InvalidConfig(String),
    #[error("invalid ldap credentials")]
    InvalidCredentials,
    #[error("invalid ldap credentials: {0}")]
    InvalidCredentialsDetail(String),
    #[error("ldap user not found")]
    UserNotFound,
    #[error("ldap user search returned multiple entries")]
    AmbiguousUser,
    #[error("ldap connection failed: {0}")]
    Connection(String),
}

/// The LDAP result code for invalid credentials.
const LDAP_RESULT_INVALID_CREDENTIALS: u32 = 49;
/// The LDAP result code for an invalid DN syntax.
const LDAP_RESULT_INVALID_DN_SYNTAX: u32 = 34;

/// The crate-local result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Connection and search settings for the LDAP server.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The LDAP server address, e.g. `ldap://host:389` or `ldaps://host:636`.
    pub url: String,
    /// Used together with [`Config::bind_password`] to search for the user
    /// (service account). Leave both empty when using
    /// [`Config::direct_bind`].
    pub bind_dn: String,
    pub bind_password: String,
    /// Authenticates by binding as the user, with no service account. Typical
    /// for Active Directory: set `user_bind_dn` to `{}` and sign in with
    /// `user@domain.com`.
    pub direct_bind: bool,
    /// A template for the bind identity; `{}` is replaced with the login
    /// username. Examples: `{}`, `{}@uet.com`, `UET\\{}`.
    pub user_bind_dn: String,
    /// Appends `@domain` to usernames without `@` (e.g. `student` becomes
    /// `student@uet.com`).
    pub domain: String,
    /// The search base, e.g. `dc=example,dc=com`. Leave empty with
    /// `direct_bind` to read `defaultNamingContext` from the RootDSE.
    pub base_dn: String,
    /// A filter template; `{}` is replaced with the escaped username.
    /// Defaults to `(uid={})`.
    pub user_filter: String,
    /// Fetched and stored on [`User::username`] (e.g. `mail`, `uid`,
    /// `sAMAccountName`).
    pub user_attribute: String,
    /// Overrides `user_attribute` for [`User::username`] when set.
    pub username_attribute: String,
    /// Maps to [`User::email`]; defaults to `mail`.
    pub email_attribute: String,
    /// Tried in order for [`User::name`]; defaults to `displayName`, `cn`.
    pub name_attributes: Vec<String>,
    /// A multi-valued LDAP attribute mapped to [`User::roles`] (e.g.
    /// `memberOf` for Active Directory).
    pub role_attribute: String,
    /// Extracts `CN=` from each role value, typical for `memberOf`. Defaults to
    /// true when `role_attribute` is `memberOf`.
    pub role_from_dn: Option<bool>,
    /// Extra LDAP attributes to fetch into [`User::attributes`].
    pub attributes: Vec<String>,
    /// Disables TLS certificate verification for `ldaps` URLs.
    pub insecure_skip_verify: bool,
    /// The TLS server name to present.
    ///
    /// The rustls backend takes SNI from the URL host, so this is only used to
    /// detect that a custom name was requested; put the certificate's hostname
    /// in [`Config::url`] instead of an IP address.
    pub tls_server_name: String,
    /// Applies to dial, bind and search operations.
    pub timeout: Duration,
}

impl Config {
    fn direct_bind_enabled(&self) -> bool {
        self.direct_bind || (self.bind_dn.trim().is_empty() && !self.user_bind_dn.trim().is_empty())
    }

    fn apply_direct_bind_defaults(&mut self) {
        if self.user_attribute.trim().is_empty() {
            self.user_attribute = "sAMAccountName".to_string();
        }
        if self.attributes.is_empty() {
            self.attributes = [
                "givenName",
                "sn",
                "mail",
                "sAMAccountName",
                "userPrincipalName",
            ]
            .into_iter()
            .map(String::from)
            .collect();
        }
        if self.name_attributes.is_empty() {
            self.name_attributes = ["displayName", "cn", "givenName"]
                .into_iter()
                .map(String::from)
                .collect();
        }
    }

    pub(crate) fn role_from_dn(&self) -> bool {
        match self.role_from_dn {
            Some(value) => value,
            None => self.role_attribute.trim().eq_ignore_ascii_case("memberOf"),
        }
    }
}

/// Authenticates users against an LDAP directory.
#[derive(Debug)]
pub struct Client {
    cfg: Config,
    /// Cached after RootDSE discovery.
    base_dn: OnceCell<String>,
}

impl Client {
    /// Validates `cfg` and returns a ready-to-use client.
    pub fn new(mut cfg: Config) -> Result<Self> {
        if cfg.url.trim().is_empty() {
            return Err(Error::InvalidConfig("url is required".into()));
        }
        if cfg.timeout.is_zero() {
            cfg.timeout = Duration::from_secs(10);
        }
        if cfg.base_dn.trim().is_empty() && !cfg.direct_bind_enabled() {
            return Err(Error::InvalidConfig(
                "base_dn is required unless direct_bind is enabled".into(),
            ));
        }
        if cfg.user_filter.trim().is_empty() {
            cfg.user_filter = if cfg.direct_bind_enabled() {
                "(&(objectClass=user)(userPrincipalName={}))".to_string()
            } else {
                "(uid={})".to_string()
            };
        }
        if cfg.direct_bind_enabled() {
            cfg.apply_direct_bind_defaults();
        }
        if !cfg.bind_dn.trim().is_empty() && cfg.bind_password.is_empty() {
            return Err(Error::InvalidConfig(
                "bind_password is required when bind_dn is set".into(),
            ));
        }
        if cfg.direct_bind_enabled()
            && cfg.user_bind_dn.trim().is_empty()
            && cfg.domain.trim().is_empty()
        {
            cfg.user_bind_dn = "{}".to_string();
        }
        if cfg.direct_bind_enabled() && !cfg.bind_dn.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "direct_bind cannot be used together with bind_dn".into(),
            ));
        }
        Ok(Self {
            cfg,
            base_dn: OnceCell::new(),
        })
    }

    /// Verifies `username` and `password` against LDAP.
    ///
    /// On success it returns the matched entry as a [`User`] with mapped and raw
    /// attributes.
    pub async fn login(&self, username: &str, password: &str) -> Result<User> {
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err(Error::InvalidCredentials);
        }

        let mut conn = self.dial().await?;

        if self.cfg.direct_bind_enabled() {
            return self.login_direct(&mut conn, username, password).await;
        }

        if !self.cfg.bind_dn.is_empty() {
            let result = conn
                .simple_bind(&self.cfg.bind_dn, &self.cfg.bind_password)
                .await
                .map_err(|err| Error::Connection(format!("service bind: {err}")))?;
            if result.rc != 0 {
                return Err(service_bind_error(result.rc, &result.text));
            }
        }

        let entry = self.search_user(&mut conn, username).await?;
        let bind = conn
            .simple_bind(&entry.dn, password)
            .await
            .map_err(|err| Error::InvalidCredentialsDetail(format!("user bind: {err}")))?;
        if bind.rc != 0 {
            return Err(bind_failure(bind.rc, &bind.text));
        }

        Ok(user_from_entry(&entry, &self.cfg))
    }

    /// Returns the configured domain.
    pub fn get_domain(&self) -> &str {
        &self.cfg.domain
    }

    /// Appends the configured domain to a bare username.
    pub fn username_with_domain(&self, username: &str) -> String {
        if username.contains('@') {
            return username.to_string();
        }
        format!("{username}@{}", self.cfg.domain)
    }

    /// The configuration this client was built with.
    pub fn get_config(&self) -> &Config {
        &self.cfg
    }

    /// Binds as the user (no service account), then loads their LDAP entry.
    async fn login_direct(&self, conn: &mut Ldap, username: &str, password: &str) -> Result<User> {
        let bind_identity = self.user_bind_identity(username);
        let bind = conn
            .simple_bind(&bind_identity, password)
            .await
            .map_err(|err| Error::InvalidCredentialsDetail(format!("user bind: {err}")))?;
        if bind.rc != 0 {
            return Err(bind_failure(bind.rc, &bind.text));
        }

        match self.search_user(conn, &bind_identity).await {
            Ok(entry) => Ok(user_from_entry(&entry, &self.cfg)),
            Err(Error::UserNotFound) => Ok(user::user_from_bind_identity(username, &bind_identity)),
            Err(err) => Err(err),
        }
    }

    fn user_bind_identity(&self, username: &str) -> String {
        if username.contains('@') {
            return username.to_string();
        }
        let template = self.cfg.user_bind_dn.trim();
        if !template.is_empty() {
            return format_template(template, username);
        }
        let domain = self.cfg.domain.trim();
        if !domain.is_empty() {
            return format!("{username}@{}", domain.trim_start_matches('@'));
        }
        username.to_string()
    }

    async fn resolve_base_dn(&self, conn: &mut Ldap) -> Result<String> {
        let configured = self.cfg.base_dn.trim();
        if !configured.is_empty() {
            return Ok(configured.to_string());
        }
        if let Some(cached) = self.base_dn.get() {
            return Ok(cached.clone());
        }
        let dn = discover_base_dn(conn).await?;
        let _ = self.base_dn.set(dn.clone());
        Ok(dn)
    }

    async fn search_user(&self, conn: &mut Ldap, search_term: &str) -> Result<SearchEntry> {
        let base_dn = self.resolve_base_dn(conn).await?;
        let filter = format_user_filter(&self.cfg.user_filter, search_term);

        conn.with_search_options(
            SearchOptions::new()
                .sizelimit(1)
                .timelimit(self.cfg.timeout.as_secs() as i32),
        );

        let result = conn
            .search(&base_dn, Scope::Subtree, &filter, self.search_attributes())
            .await
            .map_err(|err| Error::Connection(format!("search: {err}")))?;
        let (entries, _) = result
            .success()
            .map_err(|err| Error::Connection(format!("search: {err}")))?;

        match entries.len() {
            0 => Err(Error::UserNotFound),
            1 => Ok(SearchEntry::construct(entries.into_iter().next().unwrap())),
            _ => Err(Error::AmbiguousUser),
        }
    }

    async fn dial(&self) -> Result<Ldap> {
        let mut settings = LdapConnSettings::new().set_conn_timeout(self.cfg.timeout);
        if self.cfg.insecure_skip_verify {
            settings = settings.set_no_tls_verify(true);
        }
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.cfg.url)
            .await
            .map_err(|err| Error::Connection(err.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        ldap.with_timeout(self.cfg.timeout);
        Ok(ldap)
    }

    fn search_attributes(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let mut add = |name: &str| {
            let name = name.trim();
            if name.is_empty() {
                return;
            }
            if seen
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(name))
            {
                return;
            }
            seen.push(name.to_string());
        };

        add("dn");
        add(&self.cfg.user_attribute);
        add(&self.cfg.username_attribute);
        add(&first_non_empty([
            self.cfg.email_attribute.clone(),
            "mail".to_string(),
        ]));
        for attr in &self.cfg.name_attributes {
            add(attr);
        }
        if self.cfg.name_attributes.is_empty() {
            add("displayName");
            add("cn");
        }
        add(&self.cfg.role_attribute);
        for attr in &self.cfg.attributes {
            add(attr);
        }
        seen
    }
}

/// Substitutes every `{}` placeholder in a template with `value`.
fn format_template(template: &str, value: &str) -> String {
    template.replace("{}", value)
}

/// Substitutes the escaped username into a filter template.
fn format_user_filter(template: &str, username: &str) -> String {
    if !template.contains("{}") {
        return template.to_string();
    }
    format_template(template, &ldap_escape(username))
}

fn bind_failure(rc: u32, text: &str) -> Error {
    if rc == LDAP_RESULT_INVALID_CREDENTIALS || rc == LDAP_RESULT_INVALID_DN_SYNTAX {
        return Error::InvalidCredentials;
    }
    Error::InvalidCredentialsDetail(format!("user bind: {text}"))
}

fn service_bind_error(rc: u32, text: &str) -> Error {
    if rc == LDAP_RESULT_INVALID_CREDENTIALS {
        let hint = if text.to_lowercase().contains("52e") {
            "Active Directory rejected the bind (52e: wrong bind identity or password)"
        } else {
            "check bind_dn and bind_password"
        };
        return Error::Connection(format!("service bind: {hint}: {text}"));
    }
    Error::Connection(format!("service bind: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_incomplete_configs() {
        assert!(matches!(
            Client::new(Config::default()),
            Err(Error::InvalidConfig(_))
        ));

        assert!(matches!(
            Client::new(Config {
                url: "ldap://localhost:389".into(),
                ..Config::default()
            }),
            Err(Error::InvalidConfig(_))
        ));

        assert!(matches!(
            Client::new(Config {
                url: "ldap://localhost:389".into(),
                base_dn: "dc=example,dc=com".into(),
                bind_dn: "cn=svc,dc=example,dc=com".into(),
                ..Config::default()
            }),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn new_applies_direct_bind_defaults() {
        let client = Client::new(Config {
            url: "ldaps://ad.example.com:636".into(),
            direct_bind: true,
            domain: "example.com".into(),
            ..Config::default()
        })
        .expect("client builds");

        let cfg = client.get_config();
        assert_eq!(cfg.user_attribute, "sAMAccountName");
        assert_eq!(
            cfg.user_filter,
            "(&(objectClass=user)(userPrincipalName={}))"
        );
        assert_eq!(cfg.name_attributes, vec!["displayName", "cn", "givenName"]);
        assert_eq!(cfg.timeout, Duration::from_secs(10));
    }

    #[test]
    fn user_bind_identity_applies_template_and_domain() {
        let client = Client::new(Config {
            url: "ldaps://ad.example.com:636".into(),
            direct_bind: true,
            domain: "example.com".into(),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(client.user_bind_identity("student"), "student@example.com");
        assert_eq!(
            client.user_bind_identity("student@example.com"),
            "student@example.com"
        );

        let templated = Client::new(Config {
            url: "ldaps://ad.example.com:636".into(),
            direct_bind: true,
            user_bind_dn: "EXAMPLE\\{}".into(),
            ..Config::default()
        })
        .unwrap();
        assert_eq!(templated.user_bind_identity("student"), "EXAMPLE\\student");
    }

    #[test]
    fn format_user_filter_escapes_the_username() {
        assert_eq!(format_user_filter("(uid={})", "a*b"), "(uid=a\\2ab)");
        assert_eq!(
            format_user_filter("(objectClass=*)", "ignored"),
            "(objectClass=*)"
        );
    }
}
