//! The HTTP endpoints: provider listing, sign-in and OAuth callback.

use std::collections::HashMap;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::authorization::Authorization;
use crate::authorize::{AuthorizeOptions, AuthorizeOptionsFunc};
use crate::checks::{provider_uses_check, random_string};
use crate::constants::DEFAULT_BASE_PATH;
use crate::cookies::{CookieJar, expire_cookie, read_cookie, set_cookie};
use crate::errors::BoxError;
use crate::flow_intent::FLOW_INTENT_CONNECT;
use crate::http::{RequestContext, client_ip, provider_id_from_request};
use crate::oauth::{authorization_url, exchange_code, fetch_user_info};
use crate::provider::{
    Check, CredentialsProvider, CredentialsRequest, OAuthProvider, Provider, PublicProvider,
};
use crate::provider_utils::{callback_query, discover};
use crate::response::{Response, ResponseWriter, write_json};
use crate::types::{Account, JsonbArray, Profile};
use crate::user::{OAuthUser, User};
use crate::utils::format_user;

impl Authorization {
    /// Dispatches a request to the matching endpoint, the framework-agnostic
    /// equivalent of the `ServeMux` returned by Go's `Handler`.
    ///
    /// - `GET  {base}/providers`
    /// - `ANY  {base}/provider/{provider}`
    /// - `ANY  {base}/provider/{provider}/callback`
    pub async fn route<B>(&self, req: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let path = req.uri().path().to_string();
        let is_get = req.method() == http::Method::GET;

        if path == format!("{DEFAULT_BASE_PATH}/providers") && is_get {
            return self.get_providers(req).await;
        }
        if path.starts_with(&format!("{DEFAULT_BASE_PATH}/provider/")) {
            if path.ends_with("/callback") {
                return self.handle_callback(req).await;
            }
            return self.handle_sign_in(req).await;
        }
        write_json(
            StatusCode::NOT_FOUND,
            json!({ "message": "Not found", "code": "ERROR" }),
        )
    }

    /// Lists the configured providers in the Auth.js-compatible shape.
    pub async fn get_providers<B>(&self, req: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = split_request(req).await;
        let r = RequestContext::with_body(&parts, body);

        let Ok((origin, _)) = self.origin(&r) else {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "message": "Failed to get origin", "code": "ERROR" }),
            );
        };

        let providers: Vec<PublicProvider> = self
            .providers()
            .iter()
            .map(|p| PublicProvider {
                id: p.id().to_string(),
                name: p.name().to_string(),
                type_: p.type_().to_string(),
                sign_in_url: self.sign_in_url(&origin, p.id()),
                callback_url: self.callback_url(&origin, p.id()),
            })
            .collect();

        write_json(StatusCode::OK, providers)
    }

    /// Starts the sign-in flow for the provider named in the path: an OAuth
    /// redirect, or a credentials POST.
    pub async fn handle_sign_in<B>(&self, req: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = split_request(req).await;
        let r = RequestContext::with_body(&parts, body);
        let mut w = ResponseWriter::new();

        let response = self.sign_in(&mut w, &r).await;
        w.finish(response)
    }

    async fn sign_in(&self, w: &mut ResponseWriter, r: &RequestContext<'_>) -> Response {
        let Ok((origin, secure)) = self.origin(r) else {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "message": "Failed to get origin", "code": "ERROR" }),
            );
        };

        let provider_id = provider_id_from_request(r);
        let Some(p) = self.find_provider(&provider_id).cloned() else {
            return write_json(
                StatusCode::OK,
                json!({ "message": format!("unknown provider: {provider_id}") }),
            );
        };

        if let Some(oauth) = p.as_oauth() {
            return self.start_oauth(w, r, oauth, &origin, secure).await;
        }
        if let Some(credentials) = p.as_credentials() {
            return self
                .credentials_callback(w, r, credentials, &origin, secure)
                .await;
        }
        write_json(
            StatusCode::BAD_REQUEST,
            json!({ "message": "Unsupported provider type", "code": "ERROR" }),
        )
    }

    async fn start_oauth(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        p: &OAuthProvider,
        origin: &str,
        secure: bool,
    ) -> Response {
        if discover(p).await.is_err() {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "message": "Discovery failed", "code": "ERROR" }),
            );
        }
        if p.authorization_endpoint().is_empty() {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "message": "Provider missing authorization_url", "code": "ERROR" }),
            );
        }

        let jar = self.jar(secure);
        jar.expire_oauth_flow_cookies(w);

        if r.query_get("connect") == "1" {
            if let Err(err) = self.set_flow_intent_cookie(w, r, FLOW_INTENT_CONNECT) {
                return write_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "message": "Failed to set connect flow intent",
                        "code": "ERROR",
                        "error": err.to_string(),
                    }),
                );
            }
            let resource_id = r.query_get("resource_id").trim().to_string();
            if !resource_id.is_empty() {
                if let Err(err) = self.set_connect_resource_cookie(w, r, &resource_id) {
                    return write_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({
                            "message": "Failed to set connect resource id",
                            "code": "ERROR",
                            "error": err.to_string(),
                        }),
                    );
                }
            }
        } else {
            expire_cookie(w, &jar.flow_intent());
            expire_cookie(w, &jar.connect_resource());
        }

        let cb = self.callback_url(origin, p.id());

        let mut state = String::new();
        let mut verifier = String::new();
        let mut nonce = String::new();
        if provider_uses_check(p, Check::State) {
            state = random_string(32);
            set_cookie(w, &jar.state(), &state);
        }
        if provider_uses_check(p, Check::Pkce) {
            verifier = random_string(32);
            set_cookie(w, &jar.pkce_code_verifier(), &verifier);
        }
        if provider_uses_check(p, Check::Nonce) {
            nonce = random_string(32);
            set_cookie(w, &jar.nonce(), &nonce);
        }

        let target = self.callback_target(r, origin);
        if !target.is_empty() && target != origin {
            set_cookie(w, &jar.callback_url(), &target);
        }
        // Remember a token-flow preference so the callback (a GET from the
        // provider) can return tokens instead of a session cookie.
        if self.wants_tokens(r) {
            set_cookie(w, &jar.flow(), "token");
        }

        let target = authorization_url(p, &cb, &state, &verifier, &nonce);
        if target.is_empty() {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "message": "Failed to build authorization URL", "code": "ERROR" }),
            );
        }
        self.redirect_or_json(r, &target)
    }

    /// Completes a credentials sign-in.
    ///
    /// The Go implementation stops after the method and CSRF checks; this port
    /// runs the provider's `authorize` callback and issues a session, so the
    /// credentials provider is usable end to end.
    async fn credentials_callback(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        p: &CredentialsProvider,
        origin: &str,
        secure: bool,
    ) -> Response {
        if r.method() != http::Method::POST {
            return write_json(
                StatusCode::METHOD_NOT_ALLOWED,
                json!({
                    "message": "Credentials sign-in requires POST",
                    "code": "ERROR",
                    "provider": p.id(),
                    "origin": origin,
                    "secure": secure,
                }),
            );
        }
        // Token-flow (mobile/API) clients are not cookie-based, so CSRF does
        // not apply; cookie sign-in still requires the double-submit token.
        if !self.wants_tokens(r) && !self.check_csrf(r, secure) {
            return write_json(
                StatusCode::FORBIDDEN,
                json!({ "message": "Invalid CSRF token", "code": "ERROR" }),
            );
        }

        let Some(authorize) = p.authorize.clone() else {
            return write_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "message": "Provider missing authorize function",
                    "code": "ERROR",
                }),
            );
        };

        let credentials = collect_credentials(r);
        let request = CredentialsRequest {
            method: r.method().clone(),
            uri: r.uri().clone(),
            headers: r.headers().clone(),
            remote_addr: r.remote_addr(),
        };

        let oauth_user = match authorize(credentials, request).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return write_json(
                    StatusCode::UNAUTHORIZED,
                    json!({ "message": "Invalid credentials", "code": "ERROR" }),
                );
            }
            Err(err) => {
                return write_json(
                    StatusCode::UNAUTHORIZED,
                    json!({ "message": err.to_string(), "code": "ERROR" }),
                );
            }
        };

        let user = match self
            .resolve_profile_user(&oauth_user, p.id(), p.type_().as_str())
            .await
        {
            Ok(user) => user,
            Err(response) => return *response,
        };

        let account = Account {
            type_: p.type_().to_string(),
            provider: p.id().to_string(),
            provider_account_id: oauth_user.id.clone(),
            ..Account::default()
        };

        self.complete_sign_in(w, r, p.id(), &user, &account, self.wants_tokens(r))
            .await
    }

    /// Handles the provider redirect back to this application.
    pub async fn handle_callback<B>(&self, req: Request<B>) -> Response
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = split_request(req).await;
        let r = RequestContext::with_body(&parts, body);
        let mut w = ResponseWriter::new();

        let response = self.callback(&mut w, &r).await;
        w.finish(response)
    }

    async fn callback(&self, w: &mut ResponseWriter, r: &RequestContext<'_>) -> Response {
        let Ok((origin, secure)) = self.origin(r) else {
            return write_json(
                StatusCode::BAD_REQUEST,
                json!({ "message": "Failed to get origin", "code": "ERROR" }),
            );
        };

        let provider_id = provider_id_from_request(r);
        let Some(p) = self.find_provider(&provider_id).cloned() else {
            return write_json(
                StatusCode::NOT_FOUND,
                json!({
                    "message": format!("Unknown provider: {provider_id}"),
                    "code": "ERROR",
                }),
            );
        };

        if let Some(oauth) = p.as_oauth() {
            return self.oauth_callback(w, r, oauth, &origin, secure).await;
        }
        if let Some(credentials) = p.as_credentials() {
            return self
                .credentials_callback(w, r, credentials, &origin, secure)
                .await;
        }
        write_json(
            StatusCode::BAD_REQUEST,
            json!({ "message": "Unsupported provider type", "code": "ERROR" }),
        )
    }

    async fn oauth_callback(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        p: &OAuthProvider,
        origin: &str,
        secure: bool,
    ) -> Response {
        let jar = self.jar(secure);

        // Some providers (notably Sign in with Apple, when name/email scopes
        // are requested) use response_mode=form_post and deliver code/state in
        // the POST body. Merge those into the query so the rest of the handler
        // is uniform.
        let mut q = callback_query(r);

        let response = self
            .oauth_callback_inner(w, r, p, origin, &jar, &mut q)
            .await;
        jar.expire_oauth_flow_cookies(w);
        response
    }

    async fn oauth_callback_inner(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        p: &OAuthProvider,
        origin: &str,
        jar: &CookieJar,
        q: &mut HashMap<String, String>,
    ) -> Response {
        if !q
            .get("error")
            .map(String::as_str)
            .unwrap_or_default()
            .is_empty()
        {
            return self.render_callback_page(json!({
                "message": "Provider returned error",
                "code": "ERROR",
            }));
        }
        let code = q.get("code").cloned().unwrap_or_default();
        if code.is_empty() {
            return self.render_callback_page(json!({
                "message": "Missing authorization code",
                "code": "ERROR",
            }));
        }

        // Restore a token-flow preference set during start_oauth.
        if read_cookie(r, &jar.flow().name) == "token" {
            expire_cookie(w, &jar.flow());
            q.insert("flow".to_string(), "token".to_string());
        }

        if provider_uses_check(p, Check::State) {
            let expected = read_cookie(r, &jar.state().name);
            expire_cookie(w, &jar.state());
            let received = q.get("state").map(String::as_str).unwrap_or_default();
            if expected.is_empty() || !bool::from(expected.as_bytes().ct_eq(received.as_bytes())) {
                return self.render_callback_page(json!({
                    "message": "State mismatch",
                    "code": "ERROR",
                }));
            }
        }

        let mut verifier = String::new();
        if provider_uses_check(p, Check::Pkce) {
            verifier = read_cookie(r, &jar.pkce_code_verifier().name);
            expire_cookie(w, &jar.pkce_code_verifier());
        }

        if let Err(err) = discover(p).await {
            return self.render_callback_page(json!({
                "message": format!("Discovery failed: {err}"),
                "code": "ERROR",
            }));
        }

        let cb = self.callback_url(origin, p.id());
        let tokens = match exchange_code(p, &code, &cb, &verifier).await {
            Ok(tokens) => tokens,
            Err(err) => {
                return self.render_callback_page(json!({
                    "message": format!("Token exchange failed: {err}"),
                    "code": "ERROR",
                }));
            }
        };

        let mut profile = match fetch_user_info(p, &tokens).await {
            Ok(profile) => profile,
            Err(err) => {
                return self.render_callback_page(json!({
                    "message": format!("Userinfo failed: {err}"),
                    "code": "ERROR",
                }));
            }
        };

        let Some(profile_fn) = p.profile.clone() else {
            return self.render_callback_page(json!({
                "message": "Provider missing profile function",
                "code": "ERROR",
            }));
        };
        let user = match profile_fn(&profile, &tokens) {
            Ok(user) => user,
            Err(err) => {
                return self.render_callback_page(json!({
                    "message": format!("Profile mapping failed: {err}"),
                    "code": "ERROR",
                }));
            }
        };

        let mut account = Account {
            type_: p.type_().to_string(),
            provider: p.id().to_string(),
            provider_account_id: user.id.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            id_token: tokens.id_token.clone(),
            token_type: tokens.token_type.clone(),
            scope: tokens.scope.clone(),
            expires_at: tokens.expires_at(),
            ..Account::default()
        };

        let Some(resolve_user) = self.resolve_user_fn().cloned() else {
            return self.render_callback_page(json!({
                "message": "resolve_user is not set on the Authorization value",
                "code": "ERROR",
            }));
        };

        profile.insert("provider".to_string(), Value::String(p.id().to_string()));
        profile.insert(
            "providerType".to_string(),
            Value::String(p.type_().to_string()),
        );

        let resolved_user = match resolve_user(profile).await {
            Ok((user, _)) => user,
            Err(err) => {
                return self.render_callback_page(json!({
                    "message": format!("Resolve user failed: {err}"),
                    "code": "ERROR",
                }));
            }
        };
        let Some(resolved_user) = resolved_user.filter(|user| !user.id.is_empty()) else {
            return self.render_callback_page(json!({
                "message": "resolve_user returned an invalid user",
                "code": "ERROR",
            }));
        };

        if self.consume_flow_intent(w, r, jar, FLOW_INTENT_CONNECT) {
            account.user_id = resolved_user.id.clone();
            return self
                .complete_provider_connect(w, r, jar, p, &resolved_user, &account)
                .await;
        }

        self.complete_sign_in(w, r, p.id(), &resolved_user, &account, false)
            .await
    }

    async fn complete_provider_connect(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        jar: &CookieJar,
        p: &OAuthProvider,
        user: &User,
        account: &Account,
    ) -> Response {
        if user.id.is_empty() {
            return self.render_callback_page(json!({
                "message": "User is required to complete provider connect",
                "code": "ERROR",
            }));
        }

        let resource_id = self.consume_connect_resource_cookie(w, r, jar);
        if !resource_id.is_empty() {
            if let Some(on_provider_connect) = self.on_provider_connect_fn().cloned() {
                let result = on_provider_connect(
                    resource_id.clone(),
                    account.clone(),
                    user.clone(),
                    p.id().to_string(),
                )
                .await;
                if let Err(err) = result {
                    return self.render_callback_page(json!({
                        "message": format!("Failed to save provider connect content: {err}"),
                        "code": "ERROR",
                    }));
                }
            }
        }

        self.render_callback_page(json!({
            "message": "Account connected successfully.",
            "code": "SUCCESS",
            "user": user,
            "account": account,
            "provider": p.id(),
            "type": "connect",
            "resource_id": resource_id,
        }))
    }

    async fn complete_sign_in(
        &self,
        w: &mut ResponseWriter,
        r: &RequestContext<'_>,
        provider_id: &str,
        user: &User,
        account: &Account,
        as_tokens: bool,
    ) -> Response {
        if user.id.is_empty() {
            return self.render_callback_page(json!({
                "message": "User is required to complete sign-in",
                "code": "ERROR",
            }));
        }

        let mut opts: Vec<AuthorizeOptionsFunc> = vec![
            self.with_user_id(&user.id),
            self.with_user_roles(user.roles.clone()),
            self.with_account(account.clone()),
        ];
        opts.extend(self.session_meta_from_request(r, provider_id));

        let (tokens, session_id) = match self.authorize(opts).await {
            Ok(result) => result,
            Err(err) => {
                return self.render_callback_page(json!({
                    "message": format!("Authorize failed: {err}"),
                    "code": "ERROR",
                }));
            }
        };
        self.set_session_id_cookie(w, r, &session_id);

        let payload = json!({
            "type": "sign_in",
            "message": format!("Successfully signed in with {provider_id}"),
            "user": format_user(Some(user)),
            "tokens": tokens,
            "session_id": session_id,
        });

        if as_tokens {
            return write_json(StatusCode::OK, payload);
        }
        self.render_callback_page(payload)
    }

    /// Maps a provider user onto an application user through `resolve_user`,
    /// falling back to the provider identity when no resolver is configured.
    async fn resolve_profile_user(
        &self,
        oauth_user: &OAuthUser,
        provider_id: &str,
        provider_type: &str,
    ) -> std::result::Result<User, Box<Response>> {
        let Some(resolve_user) = self.resolve_user_fn().cloned() else {
            return Ok(User {
                id: oauth_user.id.clone(),
                ..User::default()
            });
        };

        let mut profile: Profile = match serde_json::to_value(oauth_user) {
            Ok(Value::Object(map)) => map,
            _ => Profile::new(),
        };
        profile.insert(
            "provider".to_string(),
            Value::String(provider_id.to_string()),
        );
        profile.insert(
            "providerType".to_string(),
            Value::String(provider_type.to_string()),
        );

        match resolve_user(profile).await {
            Ok((Some(user), _)) if !user.id.is_empty() => Ok(user),
            Ok(_) => Err(Box::new(write_json(
                StatusCode::UNAUTHORIZED,
                json!({ "message": "resolve_user returned an invalid user", "code": "ERROR" }),
            ))),
            Err(err) => Err(Box::new(write_json(
                StatusCode::UNAUTHORIZED,
                json!({ "message": err.to_string(), "code": "ERROR" }),
            ))),
        }
    }

    // --- Authorize options -------------------------------------------------

    /// Sets the user the session and tokens belong to.
    pub fn with_user_id(&self, user_id: &str) -> AuthorizeOptionsFunc {
        let user_id = user_id.to_string();
        Box::new(move |o: &mut AuthorizeOptions| o.user_id = user_id)
    }

    /// Sets the role grants embedded in the tokens.
    pub fn with_user_roles(&self, roles: JsonbArray) -> AuthorizeOptionsFunc {
        Box::new(move |o: &mut AuthorizeOptions| o.roles = roles)
    }

    /// Attaches the provider account stored on the session row.
    pub fn with_account(&self, account: Account) -> AuthorizeOptionsFunc {
        Box::new(move |o: &mut AuthorizeOptions| o.account = Some(account))
    }

    /// Records the caller's IP address on the session row.
    pub fn with_ip_address(&self, ip_address: &str) -> AuthorizeOptionsFunc {
        let ip_address = ip_address.to_string();
        Box::new(move |o: &mut AuthorizeOptions| o.ip_address = ip_address)
    }

    /// Records the caller's user agent on the session row.
    pub fn with_user_agent(&self, user_agent: &str) -> AuthorizeOptionsFunc {
        let user_agent = user_agent.to_string();
        Box::new(move |o: &mut AuthorizeOptions| o.user_agent = user_agent)
    }

    /// Records how the session was established (the provider id).
    pub fn with_method(&self, method: &str) -> AuthorizeOptionsFunc {
        let method = method.to_string();
        Box::new(move |o: &mut AuthorizeOptions| {
            if !method.is_empty() {
                o.method = method;
            }
        })
    }

    /// Captures the request metadata stored on the session row.
    pub fn session_meta_from_request(
        &self,
        r: &RequestContext<'_>,
        method: &str,
    ) -> Vec<AuthorizeOptionsFunc> {
        vec![
            self.with_ip_address(&client_ip(r)),
            self.with_user_agent(r.user_agent()),
            self.with_method(method),
        ]
    }
}

/// Splits a request into its head and a fully collected body.
async fn split_request<B>(req: Request<B>) -> (http::request::Parts, Bytes)
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let (parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    (parts, bytes)
}

/// Gathers every submitted form field as the credentials map.
fn collect_credentials(r: &RequestContext<'_>) -> HashMap<String, String> {
    let mut credentials = HashMap::new();
    for (key, values) in r.post_form() {
        if key == "csrfToken" || key == "callbackUrl" {
            continue;
        }
        if let Some(first) = values.first() {
            credentials.insert(key.clone(), first.clone());
        }
    }
    credentials
}
