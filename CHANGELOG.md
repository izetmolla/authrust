# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions are bumped automatically by [release-plz](https://release-plz.dev) from
[Conventional Commits](https://www.conventionalcommits.org/):

| Commit type | Version bump |
|-------------|--------------|
| `fix:` | **patch** (`0.1.0` → `0.1.1`) |
| `feat:` | **minor** (`0.1.0` → `0.2.0`) |
| `feat!:` / `BREAKING CHANGE:` | **major** (`0.1.0` → `1.0.0`, or minor on `0.x`) |

## [Unreleased]

## [0.1.1](https://github.com/izetmolla/authrust/compare/v0.1.0...v0.1.1) - 2026-08-10

### Other

- Refactor CI and release workflows to use actions/checkout@v5, update release-plz configuration, and clean up changelog template in release-plz.toml. Improve integration test setup and code clarity in examples and user modules.
- Update README.md to improve release information and add CI badge. Introduce a section on automated releases with release-plz, detailing the conventional commit guidelines for versioning.

## [0.1.0] - 2026-08-10

### Added

- Initial public release of `authrust`: OAuth/OIDC, credentials, LDAP, JWT sessions, tower middleware, axum integration.
