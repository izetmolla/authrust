# LDAP authentication

Small wrapper around [`ldap3`](https://docs.rs/ldap3) for verifying usernames and passwords against an LDAP directory and reading profile attributes from the matched entry.

## How it works

1. Connect to the LDAP server.
2. Bind with a service account (optional) to run the user search.
3. Find exactly one entry under `base_dn` using `user_filter` (`%s` is replaced with an escaped username).
4. Bind as that entry with the supplied password.
5. On success, return a [`User`](https://docs.rs/authrust/latest/authrust/providers/ldap/struct.User.html) with mapped fields (`name`, `email`, `roles`, …) and all requested raw LDAP attributes.

## Quick start

```rust,no_run
use authrust::providers::ldap::{Client, Config};

let client = Client::new(Config {
    url: "ldap://ldap.example.com:389".into(),
    bind_dn: "cn=readonly,dc=example,dc=com".into(),
    bind_password: "service-account-password".into(),
    base_dn: "ou=people,dc=example,dc=com".into(),
    user_filter: "(uid=%s)".into(),
    user_attribute: "uid".into(),
    email_attribute: "mail".into(),
    name_attributes: vec!["displayName".into(), "cn".into()],
    role_attribute: "memberOf".into(),
    ..Config::default()
})?;

let user = client.login("jdoe", "user-password").await?;
println!("{}", user.name);                 // Jane Doe
println!("{}", user.email);                // jdoe@example.com
println!("{:?}", user.roles);              // ["Staff", "Editors"] (CNs from memberOf)
println!("{}", user.get("department"));    // any extra attribute
println!("{}", user.identity());           // username or DN
println!("{}", user.login_email(""));      // best email/UPN for app lookup
```

## User result

After a successful `login`, you get:

| Field | Source |
|-------|--------|
| `dn` | Entry distinguished name |
| `username` | `username_attribute`, else `user_attribute` |
| `email` | `email_attribute` (default `mail`) |
| `name` | First hit from `name_attributes` (default `displayName`, then `cn`) |
| `roles` | Values from `role_attribute`; when `role_from_dn` is true, `CN=` is extracted (default for `memberOf`) |
| `attributes` | Map of every attribute requested during search |

Helpers:

- `user.get("title")` — first value for any fetched attribute
- `user.get_all("memberOf")` — all values
- `user.identity()` — `username` if set, otherwise `dn`
- `user.login_email(fallback)` — `email` → `mail` → `userPrincipalName` → `username` → fallback

## Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `url` | yes | `ldap://host:389` or `ldaps://host:636` |
| `base_dn` | yes | Search base, e.g. `dc=example,dc=com` |
| `bind_dn` | no | Service account DN for search |
| `bind_password` | no | Password for `bind_dn` |
| `user_filter` | no | Filter template; `%s` = escaped username. Default: `(uid=%s)` |
| `user_attribute` | no | Stored on `User.username` (e.g. `uid`, `mail`) |
| `username_attribute` | no | Overrides `user_attribute` for `User.username` |
| `email_attribute` | no | Default: `mail` |
| `name_attributes` | no | Default: `displayName`, `cn` |
| `role_attribute` | no | Multi-valued attribute → `User.roles` (e.g. `memberOf`) |
| `role_from_dn` | no | Extract `CN=` from role values; default `true` when `role_attribute` is `memberOf` |
| `attributes` | no | Extra LDAP attributes copied into `User.attributes` |
| `insecure_skip_verify` | no | Skip TLS verification (dev only) |
| `tls_server_name` | no | Verify cert against this hostname when connecting by IP |
| `timeout` | no | Default `10s` |
| `direct_bind` | no | Bind as the user directly (no service account) |
| `user_bind_dn` | no | Template for direct bind identity (e.g. `%s@example.com`) |
| `domain` | no | Appended for UPN-style direct binds |

## Wiring into the authorization package

LDAP validates credentials and supplies directory metadata; sessions and JWTs stay in authrust. The simplest integration is through the [credentials provider](credentials.md)'s `authorize` function:

1. `user = client.login(email, password).await?`
2. Find or provision the app user from `user.login_email("")` / `user.username`
3. Optionally sync `user.roles` into your user record or JWT `roles` claim
4. Return an `OAuthUser` (authrust creates the session and signs the token pair), or issue tokens manually with `auth.authorize(...)`

## Errors

| Variant | When |
|---------|------|
| `Error::InvalidConfig` | Missing `url` or `base_dn` in `Client::new` |
| `Error::InvalidCredentials` | Empty username/password or user bind failed |
| `Error::UserNotFound` | Search returned no entries |
| `Error::AmbiguousUser` | Search returned more than one entry |
| `Error::Connection` | Dial, service bind, or search failed |
