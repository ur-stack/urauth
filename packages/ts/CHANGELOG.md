# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-26

### Added

- TypeScript core library for JWT creation, verification, and token refresh with rotation
- Token service with access/refresh token pairs and reuse detection
- Revocation service with pluggable TokenStore
- AuthContext with permission, role, and relation checks
- Composable authorization primitives (Permission, Role, Relation, Requirement)
- Permission checkers: StringChecker and RoleExpandingChecker
- Role registry with inheritance and loader/cache interfaces
- Typed permission enums via definePermissions factory
- In-memory token and session stores for dev/testing

[Unreleased]: https://github.com/ur-stack/urauth/compare/@urauth/ts-v0.1.0...HEAD
[0.1.0]: https://github.com/ur-stack/urauth/releases/tag/@urauth/ts-v0.1.0
