# Google provider

Google sign-in for [authrust](../../README.md) using OpenID Connect discovery.

## Usage

```rust,no_run
use authrust::{Authorization, Config, providers::google};

let auth = Authorization::new(Config {
    providers: vec![
        google::new(
            &std::env::var("GOOGLE_CLIENT_ID").unwrap(),
            &std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
        ),
    ],
    // ...
    ..Config::default()
})?;
```

That is the whole configuration. Endpoints:

```
GET /api/authorization/provider/google            # start sign-in (302 to Google)
GET /api/authorization/provider/google/callback   # OAuth callback
```

## What the preset configures

| Setting | Value |
|---------|-------|
| Provider ID | `google` |
| Type | OIDC — endpoints discovered from `https://accounts.google.com/.well-known/openid-configuration` |
| Scopes | `openid`, `email`, `profile` |
| Security checks | PKCE (S256) + `state` + `nonce` |
| Profile mapping | `sub` → id, `name` → name, `email` → email, `picture` → image |

## Google Cloud Console setup

1. Create OAuth 2.0 credentials at [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials) (type *Web application*).
2. Add the authorized redirect URI, which must match your deployment exactly:

   ```
   https://your-app.example.com/api/authorization/provider/google/callback
   ```

   For local development: `http://localhost:3000/api/authorization/provider/google/callback`.
3. Pass the client ID and secret into `google::new(...)`.

The redirect URI is derived from `Config::auth_url` (or the request's `Host` / `X-Forwarded-Host` when `auth_url` is empty), so make sure `auth_url` matches what you registered.

## Customizing

`google::new` returns an `OAuthProvider` under the hood; for extra scopes or parameters, construct the provider yourself (see [providers README](README.md#writing-a-custom-oauthoidc-provider)) with `issuer: "https://accounts.google.com"`, e.g. adding offline access params to receive a refresh token from Google.
