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

## [0.1.0] - 2026-08-10

### Added

- Initial public release of `authrust`: OAuth/OIDC, credentials, LDAP, JWT sessions, tower middleware, axum integration.
