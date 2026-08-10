//! axum integration, enabled by the `axum` feature.

use axum::Router;
use axum::extract::Request;
use axum::routing::{any, get};

use crate::authorization::Authorization;
use crate::constants::DEFAULT_BASE_PATH;

impl Authorization {
    /// Returns a router serving every endpoint under
    /// [`DEFAULT_BASE_PATH`]:
    ///
    /// ```text
    /// GET  {base}/providers                    -> get_providers
    /// ANY  {base}/provider/{provider}          -> handle_sign_in
    /// ANY  {base}/provider/{provider}/callback -> handle_callback
    /// ```
    ///
    /// The three handlers are also callable individually if you prefer to
    /// register the routes yourself.
    pub fn handler(&self) -> Router {
        let providers = self.clone();
        let sign_in = self.clone();
        let callback = self.clone();

        Router::new()
            .route(
                &format!("{DEFAULT_BASE_PATH}/providers"),
                get(move |req: Request| {
                    let auth = providers.clone();
                    async move { auth.get_providers(req).await }
                }),
            )
            .route(
                &format!("{DEFAULT_BASE_PATH}/provider/{{provider}}"),
                any(move |req: Request| {
                    let auth = sign_in.clone();
                    async move { auth.handle_sign_in(req).await }
                }),
            )
            .route(
                &format!("{DEFAULT_BASE_PATH}/provider/{{provider}}/callback"),
                any(move |req: Request| {
                    let auth = callback.clone();
                    async move { auth.handle_callback(req).await }
                }),
            )
    }
}
