//! RootDSE discovery of the directory's default search base.

use ldap3::{Ldap, Scope, SearchEntry};

use super::{Error, Result};

/// Reads the search base from the RootDSE, so `base_dn` can be left unset for
/// Active Directory.
///
/// It prefers `defaultNamingContext` (Active Directory) and falls back to the
/// first `namingContexts` value (OpenLDAP and others).
pub async fn discover_base_dn(conn: &mut Ldap) -> Result<String> {
    let result = conn
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["defaultNamingContext", "namingContexts"],
        )
        .await
        .map_err(|err| Error::Connection(format!("rootdse search: {err}")))?;
    let (entries, _) = result
        .success()
        .map_err(|err| Error::Connection(format!("rootdse search: {err}")))?;

    let Some(entry) = entries.into_iter().next() else {
        return Err(Error::InvalidConfig(
            "base_dn is not set and the RootDSE returned no entries".into(),
        ));
    };
    let entry = SearchEntry::construct(entry);

    let base_dn = ["defaultNamingContext", "namingContexts"]
        .into_iter()
        .filter_map(|name| {
            entry
                .attrs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .and_then(|(_, values)| values.first())
        })
        .find(|value| !value.trim().is_empty());

    match base_dn {
        Some(dn) => Ok(dn.trim().to_string()),
        None => Err(Error::InvalidConfig(
            "base_dn is not set and could not be discovered from the RootDSE".into(),
        )),
    }
}
