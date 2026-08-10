# Credentials provider

Username/password (or any custom field set) authentication for [authrust](../../README.md). You supply the `authorize` function that validates the credentials; authrust handles the endpoint, CSRF protection, sessions, and tokens.

## Usage

```rust,no_run
use std::sync::Arc;
use authrust::{Authorization, Config, check_password, providers::credentials, user::OAuthUser};

let auth = Authorization::new(Config {
    providers: vec![
        credentials::new(credentials::Options {
            fields: vec![
                // CredentialField { name, label, type_, placeholder, ... }
            ],
            authorize: Some(Arc::new(|creds, _req| {
                Box::pin(async move {
                    let email = creds.get("email").cloned().unwrap_or_default();
                    let password = creds.get("password").cloned().unwrap_or_default();
                    // look up user; return Ok(None) for invalid credentials
                    let _ = (email, password, check_password);
                    Ok(Some(OAuthUser {
                        id: "uuid".into(),
                        ..Default::default()
                    }))
                })
            })),
            ..Default::default()
        }),
    ],
    // ...
    ..Config::default()
})?;
```

Sign-in endpoint (POST only):

```
POST /api/authorization/provider/credentials
```

## Options

| Field | Required | Description |
|-------|----------|-------------|
| `authorize` | yes | Validates the submitted credentials and returns the user, or `None` to reject |
| `id` | no | Route id, defaults to `credentials` |
| `name` | no | Display name, defaults to `Credentials` |
| `fields` | no | Describes the sign-in form inputs; returned by `GET /providers` so frontends can render the form dynamically |

## Behavior notes

- **CSRF**: browser (cookie) sign-ins must echo the signed double-submit `csrfToken` in the request body. Token-flow clients (header `X-Auth-Flow: token` or `?flow=token`) are exempt, since they are not cookie-based.
- **Method**: only `POST` is accepted; other methods get `405`.
- **Password hashing**: use `hash_password` / `check_password` (PBKDF2-SHA256, 600k iterations, self-describing `$pbkdf2-sha256$...` format) for storage.

## Pairing with LDAP

The [LDAP client](ldap.md) slots into `authorize` directly — validate against the directory, then map to your app user:

```rust,no_run
authorize: Some(Arc::new(move |creds, _req| {
    let client = ldap_client.clone();
    Box::pin(async move {
        let username = creds.get("username").cloned().unwrap_or_default();
        let password = creds.get("password").cloned().unwrap_or_default();
        let entry = match client.login(&username, &password).await {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        Ok(Some(OAuthUser {
            id: entry.identity(),
            email: entry.login_email(""),
            name: entry.name,
            ..Default::default()
        }))
    })
}))
```
