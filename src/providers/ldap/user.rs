//! The directory entry returned by a successful login.

use std::collections::HashMap;

use ldap3::SearchEntry;

use super::Config;

/// An authenticated LDAP user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// The distinguished name of the matched entry.
    pub dn: String,
    /// Taken from [`Config::username_attribute`], falling back to
    /// [`Config::user_attribute`].
    pub username: String,
    /// Taken from [`Config::email_attribute`], defaulting to `mail`.
    pub email: String,
    /// The first non-empty value of [`Config::name_attributes`].
    pub name: String,
    /// The values of [`Config::role_attribute`], reduced to their `CN=` part
    /// when [`Config::role_from_dn`](field@Config::role_from_dn) applies.
    pub roles: Vec<String>,
    /// Every attribute returned by the search, keyed by attribute name.
    pub attributes: HashMap<String, Vec<String>>,
}

impl User {
    /// Returns the first value of an attribute, matched case-insensitively.
    pub fn get(&self, attribute: &str) -> String {
        self.get_all(attribute).first().cloned().unwrap_or_default()
    }

    /// Returns every value of an attribute, matched case-insensitively.
    pub fn get_all(&self, attribute: &str) -> Vec<String> {
        self.attributes
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(attribute))
            .map(|(_, values)| values.clone())
            .unwrap_or_default()
    }

    /// The best stable identifier for this user: the username, then the DN
    /// (mirrors goauth's `Identity`).
    pub fn identity(&self) -> String {
        if !self.username.trim().is_empty() {
            return self.username.clone();
        }
        self.dn.clone()
    }

    /// Best email/UPN to look up the app user after LDAP auth
    /// (mirrors goauth's `LoginEmail`).
    ///
    /// Prefers `email`, then `mail`, `userPrincipalName`, `username`, then
    /// `fallback`.
    pub fn login_email(&self, fallback: &str) -> String {
        let mail = self.get("mail");
        let upn = self.get("userPrincipalName");
        for value in [
            self.email.as_str(),
            mail.as_str(),
            upn.as_str(),
            self.username.as_str(),
        ] {
            if !value.trim().is_empty() {
                return value.to_string();
            }
        }
        fallback.to_string()
    }
}

/// Returns the first non-empty value, or `""`.
pub fn first_non_empty(values: impl IntoIterator<Item = String>) -> String {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

/// Maps a search result onto a [`User`] using the configured attribute names.
pub(super) fn user_from_entry(entry: &SearchEntry, cfg: &Config) -> User {
    let attributes = entry.attrs.clone();
    let value = |name: &str| attribute_value(&attributes, name);

    let username = first_non_empty([
        value(&cfg.username_attribute),
        value(&cfg.user_attribute),
        value("uid"),
        value("sAMAccountName"),
        value("userPrincipalName"),
    ]);

    let email_attribute = if cfg.email_attribute.trim().is_empty() {
        "mail"
    } else {
        cfg.email_attribute.trim()
    };
    let email = first_non_empty([value(email_attribute), value("userPrincipalName")]);

    let mut name_candidates: Vec<String> = cfg.name_attributes.iter().map(|a| value(a)).collect();
    if cfg.name_attributes.is_empty() {
        name_candidates = vec![value("displayName"), value("cn")];
    }
    let name = first_non_empty(name_candidates);

    let mut roles = attribute_values(&attributes, &cfg.role_attribute);
    if cfg.role_from_dn() {
        roles = cn_from_dns(&roles);
    }

    User {
        dn: entry.dn.clone(),
        username,
        email,
        name,
        roles,
        attributes,
    }
}

/// Builds a minimal user for a direct bind that succeeded but whose entry could
/// not be read back (for example when the account may not search the
/// directory).
pub(super) fn user_from_bind_identity(username: &str, bind_identity: &str) -> User {
    let email = if bind_identity.contains('@') {
        bind_identity.to_string()
    } else {
        String::new()
    };
    User {
        dn: String::new(),
        username: username.to_string(),
        email,
        name: username.to_string(),
        roles: Vec::new(),
        attributes: HashMap::new(),
    }
}

fn attribute_value(attributes: &HashMap<String, Vec<String>>, name: &str) -> String {
    attribute_values(attributes, name)
        .first()
        .cloned()
        .unwrap_or_default()
}

fn attribute_values(attributes: &HashMap<String, Vec<String>>, name: &str) -> Vec<String> {
    let name = name.trim();
    if name.is_empty() {
        return Vec::new();
    }
    attributes
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, values)| values.clone())
        .unwrap_or_default()
}

/// Reduces `CN=Admins,OU=Groups,DC=example,DC=com` to `Admins`.
fn cn_from_dns(values: &[String]) -> Vec<String> {
    values.iter().map(|value| cn_from_dn(value)).collect()
}

fn cn_from_dn(value: &str) -> String {
    for part in value.split(',') {
        let part = part.trim();
        if let Some(cn) = part
            .strip_prefix("CN=")
            .or_else(|| part.strip_prefix("cn="))
        {
            return cn.to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> SearchEntry {
        SearchEntry {
            dn: "cn=jane,dc=example,dc=com".into(),
            attrs: HashMap::from([
                ("sAMAccountName".to_string(), vec!["jane".to_string()]),
                ("mail".to_string(), vec!["jane@example.com".to_string()]),
                ("displayName".to_string(), vec!["Jane Doe".to_string()]),
                (
                    "memberOf".to_string(),
                    vec![
                        "CN=Admins,OU=Groups,DC=example,DC=com".to_string(),
                        "CN=Staff,OU=Groups,DC=example,DC=com".to_string(),
                    ],
                ),
            ]),
            bin_attrs: HashMap::new(),
        }
    }

    #[test]
    fn maps_the_configured_attributes() {
        let cfg = Config {
            user_attribute: "sAMAccountName".into(),
            role_attribute: "memberOf".into(),
            ..Config::default()
        };
        let user = user_from_entry(&entry(), &cfg);

        assert_eq!(user.dn, "cn=jane,dc=example,dc=com");
        assert_eq!(user.username, "jane");
        assert_eq!(user.email, "jane@example.com");
        assert_eq!(user.name, "Jane Doe");
        assert_eq!(user.roles, vec!["Admins", "Staff"]);
        assert_eq!(user.identity(), "jane");
        assert_eq!(user.login_email("fallback"), "jane@example.com");
    }

    #[test]
    fn identity_prefers_username_then_dn() {
        let user = User {
            dn: "cn=jane,dc=example,dc=com".into(),
            email: "jane@example.com".into(),
            ..User::default()
        };
        assert_eq!(user.identity(), "cn=jane,dc=example,dc=com");

        let with_username = User {
            username: "jane".into(),
            ..user
        };
        assert_eq!(with_username.identity(), "jane");
    }

    #[test]
    fn login_email_falls_back_through_attributes() {
        let mut user = User {
            attributes: HashMap::from([(
                "userPrincipalName".to_string(),
                vec!["jane@corp.local".to_string()],
            )]),
            ..User::default()
        };
        assert_eq!(user.login_email("fallback"), "jane@corp.local");

        user.username = "jane".into();
        user.attributes.clear();
        assert_eq!(user.login_email("fallback"), "jane");

        user.username.clear();
        assert_eq!(user.login_email("fallback"), "fallback");
    }

    #[test]
    fn keeps_full_role_dns_when_asked() {
        let cfg = Config {
            role_attribute: "memberOf".into(),
            role_from_dn: Some(false),
            ..Config::default()
        };
        let user = user_from_entry(&entry(), &cfg);
        assert_eq!(user.roles[0], "CN=Admins,OU=Groups,DC=example,DC=com");
    }

    #[test]
    fn attribute_lookup_ignores_case() {
        let cfg = Config::default();
        let user = user_from_entry(&entry(), &cfg);
        assert_eq!(user.get("samaccountname"), "jane");
        assert_eq!(user.get_all("MEMBEROF").len(), 2);
        assert_eq!(user.get("missing"), "");
    }
}
