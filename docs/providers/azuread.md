# Azure AD / Microsoft Entra ID provider

Microsoft sign-in for [authrust](../../README.md) using the Azure AD **v2.0** OAuth/OIDC endpoints and the Microsoft Graph `/me` endpoint for profile data.

## Usage

```rust,no_run
use authrust::{Authorization, Config, providers::azuread};

let auth = Authorization::new(Config {
    providers: vec![
        azuread::new(azuread::Options {
            client_id: std::env::var("AZURE_CLIENT_ID").unwrap(),
            client_secret: std::env::var("AZURE_CLIENT_SECRET").unwrap(),
            tenant_id: std::env::var("AZURE_TENANT_ID").unwrap_or_else(|_| "common".into()),
            ..Default::default()
        }),
    ],
    // ...
    ..Config::default()
})?;
```

Endpoints:

```
GET /api/authorization/provider/azuread-v2            # start sign-in
GET /api/authorization/provider/azuread-v2/callback   # OAuth callback
```

## Options

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | yes | Application (client) ID from the Azure portal |
| `client_secret` | yes | Client secret generated in the Azure portal |
| `tenant_id` | no | Who may sign in: a tenant GUID (single-tenant), `common` (any AAD or personal account, **default**), `organizations` (any AAD account), or `consumers` (personal accounts only) |
| `scopes` | no | Overrides the defaults `openid profile email User.Read`; add Graph permissions like `Files.Read`, `Mail.Send`, `offline_access` here |
| `authorization_params` | no | Extra query parameters appended to the authorize request (e.g. `prompt=select_account`) |
| `profile` | no | Overrides `azuread::default_profile` for custom user mapping |

## What the preset configures

| Setting | Value |
|---------|-------|
| Provider ID | `azuread-v2` |
| Authorize / token URLs | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token}` |
| User info | `https://graph.microsoft.com/v1.0/me` |
| Security checks | PKCE (S256) + `state` + `nonce` |
| Profile mapping | Handles both OIDC id_token claims and Graph fields: `sub`/`id`/`oid` → id, `name`/`displayName` → name, `email`/`mail`/`userPrincipalName` → email |

## Azure portal setup

1. Register an application under **Microsoft Entra ID → App registrations**.
2. Add a **Web** redirect URI matching your deployment:

   ```
   https://your-app.example.com/api/authorization/provider/azuread-v2/callback
   ```

3. Create a client secret under **Certificates & secrets**.
4. Grant the API permissions your scopes require (delegated `User.Read` is included by default).

## Connect flow (linking extra scopes)

Azure AD works with authrust's provider-**connect** flow: send a signed-in user to

```
/api/authorization/provider/azuread-v2?connect=1&resource_id=<uuid>
```

and after consent the `Config::on_provider_connect` callback receives the `resource_id`, the OAuth `Account` (with the granted tokens/scopes), and the user — useful for attaching Microsoft Graph access (mail, files, calendar) to an existing account. Include the extra Graph scopes and `offline_access` in `Options.scopes` to receive a refresh token.
