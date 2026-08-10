//! Role parsing and the `name:perms` grant model.

use std::collections::HashSet;

use serde_json::Value;

use crate::authorization::Authorization;
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::types::JsonbArray;

impl Authorization {
    /// Extracts the `roles` claim as a list of grants. Several encodings are
    /// accepted because the claim crosses JSON, JWT and database boundaries.
    pub fn get_roles(&self, r: &RequestContext<'_>) -> Result<Vec<String>> {
        let claims = self.get_claims(r)?;
        match claims.get("roles") {
            None | Some(Value::Null) => Err(Error::InvalidRoles),
            Some(raw) => roles_from_any(raw),
        }
    }

    /// Checks authorization against endpoint role names and user role grants.
    ///
    /// `endpoint_roles` are plain names required by the route (e.g. `admin`,
    /// `hr`). `user_roles` use `name:perms` where perms is `r` (read), `w`
    /// (write), or `rw` (both).
    ///
    /// Returns `(has_role, can_read, can_write)`:
    ///
    /// - `has_role`: the user has at least one endpoint role (the name before
    ///   `:` matched)
    /// - `can_read`: a matched grant includes `r` or `rw`
    /// - `can_write`: a matched grant includes `w` or `rw`
    pub fn get_role(&self, endpoint_roles: &[String], user_roles: &[String]) -> (bool, bool, bool) {
        if endpoint_roles.is_empty() || user_roles.is_empty() {
            return (false, false, false);
        }

        let mut allowed: HashSet<String> = HashSet::with_capacity(endpoint_roles.len());
        for role in endpoint_roles {
            let mut role = role.trim();
            if role.is_empty() {
                continue;
            }
            // Allow endpoint config like "admin:rw" — only the role name is compared.
            if let Some((name, _)) = role.split_once(':') {
                role = name.trim();
            }
            allowed.insert(role.to_lowercase());
        }
        if allowed.is_empty() {
            return (false, false, false);
        }

        let (mut has_role, mut can_read, mut can_write) = (false, false, false);
        for user_role in user_roles {
            let Some((name, perms)) = parse_user_role_grant(user_role) else {
                continue;
            };
            if !allowed.contains(&name.to_lowercase()) {
                continue;
            }
            has_role = true;
            if role_grant_allows_read(&perms) {
                can_read = true;
            }
            if role_grant_allows_write(&perms) {
                can_write = true;
            }
        }
        (has_role, can_read, can_write)
    }
}

fn parse_user_role_grant(user_role: &str) -> Option<(String, String)> {
    let user_role = user_role.trim();
    if user_role.is_empty() {
        return None;
    }
    let (name, perms) = match user_role.split_once(':') {
        Some((name, perms)) => (name.trim(), perms.trim().to_lowercase()),
        None => (user_role, String::new()),
    };
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), perms))
}

fn role_grant_allows_read(perms: &str) -> bool {
    perms.contains('r')
}

fn role_grant_allows_write(perms: &str) -> bool {
    perms.contains('w')
}

/// Decodes whatever the JWT library handed us for the `roles` claim into a
/// clean list of grants.
///
/// JWT claims decode JSON arrays as arrays of values, so that branch is the hot
/// path for API requests. All array shapes are funnelled through
/// [`format_roles`] so trimming and blank-dropping behave identically
/// everywhere.
pub fn roles_from_any(raw: &Value) -> Result<Vec<String>> {
    match raw {
        Value::Array(items) => Ok(format_roles(&JsonbArray(items.clone()))),
        Value::String(v) => {
            let s = v.trim();
            if s.is_empty() {
                return Err(Error::InvalidRoles);
            }
            // A JSON-encoded array (e.g. `["admin:rw","hr:r"]`) must be parsed,
            // not wrapped as a single grant string.
            if s.starts_with('[') {
                let arr: Vec<Value> = serde_json::from_str(s).map_err(|_| Error::InvalidRoles)?;
                return Ok(format_roles(&JsonbArray(arr)));
            }
            Ok(vec![s.to_string()])
        }
        _ => Err(Error::InvalidRoles),
    }
}

/// Converts a JSONB role list into grant strings (e.g. `admin:rw`), dropping
/// non-string and blank entries.
pub fn format_roles(roles: &JsonbArray) -> Vec<String> {
    if roles.is_empty() {
        return Vec::new();
    }
    normalize_role_grants(role_grants_from_any_slice(roles))
}

fn normalize_role_grants<I, S>(grants: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    grants
        .into_iter()
        .filter_map(|grant| {
            let trimmed = grant.as_ref().trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect()
}

fn role_grants_from_any_slice(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Value::String(v) => {
                let trimmed = v.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Config;
    use serde_json::json;

    #[test]
    fn format_roles_normalizes_grants() {
        let cases: Vec<(&str, JsonbArray, Vec<String>)> = vec![
            ("empty", JsonbArray::new(), vec![]),
            (
                "multiple grants",
                JsonbArray(vec![json!("admin:rw"), json!("hr:r")]),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
            (
                "single grant",
                JsonbArray(vec![json!("admin:rw")]),
                vec!["admin:rw".into()],
            ),
            (
                "trims whitespace and drops blank entries",
                JsonbArray(vec![
                    json!("  admin:rw  "),
                    json!(""),
                    json!("   "),
                    json!("hr:r"),
                ]),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
            (
                "skips non-string elements",
                JsonbArray(vec![
                    json!("admin:rw"),
                    json!(42),
                    json!(null),
                    json!("hr:r"),
                ]),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
        ];

        for (name, roles, want) in cases {
            assert_eq!(format_roles(&roles), want, "{name}");
        }
    }

    #[test]
    fn roles_from_any_accepts_every_encoding() {
        let cases: Vec<(&str, Value, Vec<String>)> = vec![
            (
                "string array",
                json!(["admin:rw", "  hr:r  ", ""]),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
            (
                // JWT claims decode JSON arrays as arrays of values; non-string
                // entries must be skipped, not turn into an error.
                "array with non-string entries",
                json!(["admin:rw", null, 42.0, "hr:r"]),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
            (
                "single grant string",
                json!("admin:rw"),
                vec!["admin:rw".into()],
            ),
            (
                // A JSON-encoded array must be parsed into individual grants,
                // not treated as one giant grant string.
                "json-encoded array string",
                json!(r#"["admin:rw","hr:r"]"#),
                vec!["admin:rw".into(), "hr:r".into()],
            ),
        ];
        for (name, raw, want) in cases {
            assert_eq!(roles_from_any(&raw).expect(name), want, "{name}");
        }

        for (name, raw) in [
            ("malformed json array string", json!(r#"["admin:rw""#)),
            ("empty string", json!("   ")),
            ("unsupported type", json!(42)),
        ] {
            assert!(roles_from_any(&raw).is_err(), "{name}");
        }
    }

    #[test]
    fn get_role_matches_grants() {
        let a = Authorization::from_config_unchecked(Config::default());
        let roles =
            |values: &[&str]| -> Vec<String> { values.iter().map(|v| v.to_string()).collect() };

        /// name, endpoint roles, user roles, expected (has, read, write)
        type Case = (&'static str, Vec<String>, Vec<String>, (bool, bool, bool));

        let cases: Vec<Case> = vec![
            (
                "read-write grant",
                roles(&["admin"]),
                roles(&["admin:rw"]),
                (true, true, true),
            ),
            (
                "read-only grant",
                roles(&["hr"]),
                roles(&["hr:r"]),
                (true, true, false),
            ),
            (
                "write-only grant",
                roles(&["hr"]),
                roles(&["hr:w"]),
                (true, false, true),
            ),
            (
                "case-insensitive name match",
                roles(&["Admin"]),
                roles(&["ADMIN:rw"]),
                (true, true, true),
            ),
            (
                "endpoint role with perms suffix compares name only",
                roles(&["admin:rw"]),
                roles(&["admin:r"]),
                (true, true, false),
            ),
            (
                "no matching role",
                roles(&["finance"]),
                roles(&["admin:rw"]),
                (false, false, false),
            ),
            (
                "empty user roles",
                roles(&["admin"]),
                vec![],
                (false, false, false),
            ),
            (
                "grant without perms matches but grants nothing",
                roles(&["admin"]),
                roles(&["admin"]),
                (true, false, false),
            ),
        ];

        for (name, endpoint_roles, user_roles, want) in cases {
            assert_eq!(a.get_role(&endpoint_roles, &user_roles), want, "{name}");
        }
    }
}
