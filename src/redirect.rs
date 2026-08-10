//! Post-action redirect resolution.

use crate::authorization::Authorization;
use crate::cookies::read_cookie;
use crate::http::RequestContext;

impl Authorization {
    /// Extracts the requested post-action redirect target from the form, query
    /// or cookie, defaulting to the origin.
    pub fn callback_target(&self, r: &RequestContext<'_>, origin: &str) -> String {
        let form_value = r.form_value("callbackUrl");
        if !form_value.is_empty() {
            return form_value.to_string();
        }
        let query_value = r.query_get("callbackUrl");
        if !query_value.is_empty() {
            return query_value.to_string();
        }
        let jar = self.jar(origin.starts_with("https"));
        let cookie_value = read_cookie(r, &jar.callback_url().name);
        if !cookie_value.is_empty() {
            return cookie_value;
        }
        origin.to_string()
    }
}
