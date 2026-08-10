//! Provider payload types and the JSONB helpers used for database columns.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::errors::{Error, Result};

/// The raw, provider-specific user payload returned from an OAuth/OIDC userinfo
/// endpoint or decoded ID token. Providers map it into a user via their
/// `profile` function.
pub type Profile = JsonMap<String, Value>;

/// Links a user to a provider login. For OAuth/OIDC providers it holds the
/// issued tokens; this mirrors the Auth.js `Account` model used by adapters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(rename = "userId", default, skip_serializing_if = "String::is_empty")]
    pub user_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub provider: String,
    #[serde(rename = "providerAccountId")]
    pub provider_account_id: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_state: String,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// The response of an OAuth 2.0 / OIDC token endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenSet {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: i64,
    #[serde(default)]
    pub scope: String,

    /// Every field returned by the provider, including non-standard ones, so
    /// callbacks can read them.
    #[serde(skip)]
    pub raw: JsonMap<String, Value>,
}

impl TokenSet {
    /// Converts the relative `expires_in` into an absolute unix timestamp.
    pub fn expires_at(&self) -> i64 {
        if self.expires_in <= 0 {
            return 0;
        }
        Utc::now().timestamp() + self.expires_in
    }
}

/// Coerces a JSON scalar into a string. OAuth providers are inconsistent about
/// returning ids as numbers vs strings, so numeric kinds are handled too.
pub fn as_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// A map of string keys to arbitrary values, used to store JSON data in a
/// `jsonb` column.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonbAny(pub JsonMap<String, Value>);

impl JsonbAny {
    /// An empty object.
    pub fn new() -> Self {
        Self(JsonMap::new())
    }

    /// Renders the map as a JSON object, falling back to `{}` on failure. This
    /// is the value written to the database column.
    pub fn to_value(&self) -> Value {
        Value::Object(self.0.clone())
    }

    /// Reads a database value back into the map. A SQL `NULL` yields an empty
    /// object, matching the Go `Scan` implementation.
    pub fn scan(value: Option<&Value>) -> Result<Self> {
        match value {
            None | Some(Value::Null) => Ok(Self::new()),
            Some(Value::Object(map)) => Ok(Self(map.clone())),
            Some(Value::String(raw)) => {
                if raw.is_empty() || raw == "null" {
                    return Ok(Self::new());
                }
                Ok(Self(serde_json::from_str(raw)?))
            }
            Some(other) => Err(Error::msg(format!(
                "failed to scan JsonbAny: unsupported value {other}"
            ))),
        }
    }

    /// Renders the map as a JSON string, falling back to `{}` on failure.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_else(|_| "{}".to_string())
    }

    /// Reports whether the map holds no entries. Used to omit empty claims.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for JsonbAny {
    type Target = JsonMap<String, Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JsonbAny {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<JsonMap<String, Value>> for JsonbAny {
    fn from(map: JsonMap<String, Value>) -> Self {
        Self(map)
    }
}

impl From<BTreeMap<String, Value>> for JsonbAny {
    fn from(map: BTreeMap<String, Value>) -> Self {
        Self(map.into_iter().collect())
    }
}

/// A positional JSONB list. Roles are stored in this shape.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonbArray(pub Vec<Value>);

impl JsonbArray {
    /// An empty list.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Renders the list as a JSON array. This is the value written to the
    /// database column.
    pub fn to_value(&self) -> Value {
        Value::Array(self.0.clone())
    }

    /// Reads a database value back into the list. A SQL `NULL` yields an empty
    /// list, matching the Go `Scan` implementation.
    pub fn scan(value: Option<&Value>) -> Result<Self> {
        match value {
            None | Some(Value::Null) => Ok(Self::new()),
            Some(Value::Array(items)) => Ok(Self(items.clone())),
            Some(Value::String(raw)) => {
                if raw.is_empty() {
                    return Ok(Self::new());
                }
                Ok(Self(serde_json::from_str(raw)?))
            }
            Some(other) => Err(Error::msg(format!("invalid JsonbArray value {other}"))),
        }
    }

    /// Renders the list as a JSON string, falling back to `[]` on failure.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_else(|_| "[]".to_string())
    }

    /// Reports whether the list holds no entries. Used to omit empty claims.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for JsonbArray {
    type Target = Vec<Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JsonbArray {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Value>> for JsonbArray {
    fn from(items: Vec<Value>) -> Self {
        Self(items)
    }
}

impl<S: Into<String>> FromIterator<S> for JsonbArray {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self(iter.into_iter().map(|s| Value::String(s.into())).collect())
    }
}
