# authrust providers

Providers describe **how a user proves who they are**. They are registered on [`Config::providers`](../README.md#configuration) and served by the sign-in / callback endpoints (see the [root README](../README.md#http-endpoints)).

## Available presets

| Provider | Module | Type | README |
|----------|--------|------|--------|
| Google | `providers::google` | OIDC (discovery, PKCE + state + nonce) | [google.md](google.md) |
| Azure AD / Entra ID | `providers::azuread` | OIDC v2.0 + Microsoft Graph profile | [azuread.md](azuread.md) |
| Credentials | `providers::credentials` | Username/password via custom `authorize` | [credentials.md](credentials.md) |
| LDAP / Active Directory | `providers::ldap` | Directory bind + attribute/role mapping | [ldap.md](ldap.md) |

```rust,no_run
use authrust::{Authorization, Config, providers::{google, azuread, credentials}};

let auth = Authorization::new(Config {
    providers: vec![
        google::new("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
        azuread::new(azuread::Options {
            client_id: id.into(),
            client_secret: secret.into(),
            tenant_id: tenant.into(),
            ..Default::default()
        }),
        credentials::new(credentials::Options {
            authorize: Some(/* ... */),
            ..Default::default()
        }),
    ],
    // ...
    ..Config::default()
})?;
```

Each provider is reachable at:

```
GET/POST /api/authorization/provider/{id}            # start sign-in
GET/POST /api/authorization/provider/{id}/callback   # OAuth callback
```

and listed by `GET /api/authorization/providers`.

## The provider model

Every provider implements the [`Provider`](https://docs.rs/authrust/latest/authrust/trait.Provider.html) trait:

- `id()` — unique, URL-safe id used in routes (`"google"`)
- `name()` — display name (`"Google"`)
- `type_()` — `oauth` | `oidc` | `credentials` | `email` | `passkey`

Concrete types in the crate root:

- **`OAuthProvider`** — any OAuth 2.0 / OpenID Connect service. Endpoints can be set explicitly (`authorization_url`, `token_url`, `user_info_url`) or discovered from an OIDC `issuer` (`/.well-known/openid-configuration`). Security checks (`Check::Pkce`, `Check::State`, `Check::Nonce`) are opt-in per provider.
- **`CredentialsProvider`** — arbitrary credentials validated by a user-supplied `authorize` function.

## From provider profile to your user

OAuth providers return a raw profile (`Profile`, a JSON object). Two mapping steps run on the callback:

1. **`OAuthProvider.profile`** (per provider) normalizes the raw payload into an `OAuthUser` (id, email, name, avatar, …). The presets ship a sensible default.
2. **`Config::resolve_user`** (yours, required) receives the profile — enriched with `provider` and `providerType` — and returns the user from **your** database (`User` with `id` and `roles`). This is where you look up or provision accounts.

After `resolve_user` succeeds, authrust creates the session, signs the token pair, sets the session cookie, and renders the callback page.

## Writing a custom OAuth/OIDC provider

No special package is needed — construct an `OAuthProvider` directly:

```rust,no_run
use std::sync::Arc;
use authrust::{Check, OAuthProvider, OAuthUser, Provider, ProviderType, providers::common};

fn github(client_id: &str, client_secret: &str) -> Arc<dyn Provider> {
    Arc::new(OAuthProvider {
        provider_id: "github".into(),
        display_name: "GitHub".into(),
        kind: Some(ProviderType::Oauth),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        authorization_url: "https://github.com/login/oauth/authorize".into(),
        token_url: "https://github.com/login/oauth/access_token".into(),
        user_info_url: "https://api.github.com/user".into(),
        scopes: vec!["read:user".into(), "user:email".into()],
        checks: vec![Check::State],
        profile: Some(Arc::new(|p, _tokens| {
            Ok(OAuthUser {
                id: common::string(p.get("id")),
                name: common::string(p.get("name")),
                email: common::string(p.get("email")),
                image: common::string(p.get("avatar_url")),
                ..Default::default()
            })
        })),
        ..Default::default()
    })
}
```

For OIDC services, set `issuer` instead of the three endpoint URLs and authrust discovers them automatically.

Notes:

- `authorization_params` appends extra parameters to the authorize redirect (e.g. `prompt`, `access_type`).
- `authorization_style: "header"` sends client credentials as HTTP Basic to the token endpoint instead of in the form body.
- `TokenSet.raw` preserves every non-standard field the token endpoint returned, so `profile` can read provider-specific data.
