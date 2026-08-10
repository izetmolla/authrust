//! Helpers shared by the provider presets.

use std::collections::HashMap;

use serde_json::Value;

use crate::provider::UrlValues;

/// Coerces a JSON scalar (as decoded from a userinfo/profile payload) into a
/// string. OAuth providers are inconsistent about returning ids as numbers vs
/// strings, so numeric kinds are handled too.
pub fn string(v: Option<&Value>) -> String {
    crate::types::as_string(v)
}

/// Returns the first non-empty string, or `""`.
pub fn first_non_empty(values: impl IntoIterator<Item = String>) -> String {
    values
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

/// Converts a flat string map into the multimap shape used for provider
/// authorization parameters. Returns an empty map for an empty input.
pub fn values(m: HashMap<String, String>) -> UrlValues {
    m.into_iter().map(|(k, v)| (k, vec![v])).collect()
}
