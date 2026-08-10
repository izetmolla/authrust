//! The target resource id carried through a provider-connect OAuth round-trip.

use uuid::Uuid;

use crate::authorization::Authorization;
use crate::cookies::{CookieJar, expire_cookie, read_cookie, set_cookie};
use crate::errors::{Error, Result};
use crate::http::RequestContext;
use crate::response::ResponseWriter;

impl Authorization {
    /// Stores the target resource id for a provider-connect OAuth round-trip.
    pub fn set_connect_resource_cookie(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        resource_id: &str,
    ) -> Result<()> {
        let resource_id = resource_id.trim();
        if resource_id.is_empty() {
            return Err(Error::msg("resource id is required"));
        }
        if Uuid::parse_str(resource_id).is_err() {
            return Err(Error::msg("resource id must be a valid uuid"));
        }
        let (_, secure) = self.origin(r)?;
        set_cookie(w, &self.jar(secure).connect_resource(), resource_id);
        Ok(())
    }

    /// Reads and clears the connect-resource cookie.
    pub fn consume_connect_resource_cookie(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        jar: &CookieJar,
    ) -> String {
        let resource_id = read_cookie(r, &jar.connect_resource().name)
            .trim()
            .to_string();
        expire_cookie(w, &jar.connect_resource());
        resource_id
    }
}
