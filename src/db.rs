//! Small helpers over `sqlx` that stand in for GORM's dynamic table names and
//! loose string/UUID identifier handling.

use uuid::Uuid;

/// Marks a statement built at runtime as safe to execute.
///
/// The only interpolated fragments are the configured table names, which go
/// through [`quote_ident`]; every value reaching a query is sent as a bind
/// parameter.
///
/// Returns the SQL string directly for `sqlx` 0.8 compatibility (`AssertSqlSafe`
/// exists only in `sqlx` 0.9+).
pub(crate) fn safe_sql(sql: String) -> String {
    sql
}

/// Quotes a possibly schema-qualified SQL identifier so a configured table name
/// can be interpolated into a query safely.
pub(crate) fn quote_ident(name: &str) -> String {
    name.split('.')
        .map(|part| format!("\"{}\"", part.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(".")
}

/// A primary key value that may live in either a `uuid` or a text column.
///
/// GORM sends every id as text and lets PostgreSQL infer the parameter type;
/// `sqlx` sends an explicit type OID, so the value has to be bound as the right
/// Rust type for `id = $1` to work against a `uuid` column.
pub(crate) enum IdValue {
    Uuid(Uuid),
    Text(String),
}

/// Classifies an identifier so it can be bound with the matching type.
pub(crate) fn id_value(raw: &str) -> IdValue {
    match Uuid::parse_str(raw) {
        Ok(uuid) => IdValue::Uuid(uuid),
        Err(_) => IdValue::Text(raw.to_string()),
    }
}

/// Binds an identifier to a query, choosing the `uuid` or text representation.
macro_rules! bind_id {
    ($query:expr, $id:expr) => {
        match $crate::db::id_value($id) {
            $crate::db::IdValue::Uuid(value) => $query.bind(value),
            $crate::db::IdValue::Text(value) => $query.bind(value),
        }
    };
}

pub(crate) use bind_id;
