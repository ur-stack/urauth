# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-26

### Added

- Framework-agnostic core auth library with JWT, OAuth2, RBAC, and multi-tenant support
- FastAPI adapter with guards, access control, and pre-built routes
- Token service with access/refresh token creation and validation
- Password hashing with bcrypt
- Composable authorization primitives (Permission, Role, Relation, Requirement)
- Permission checkers: StringChecker and RoleExpandingChecker
- Role registry with inheritance and DB-backed loader support
- Session management with Redis and in-memory backends
- Pluggable token transport (bearer, cookie, header, hybrid)
- CSRF and token refresh middleware
- Typed permission enums via definePermissions factory

[Unreleased]: https://github.com/ur-stack/urauth/compare/urauth-py-v0.1.0...HEAD
[0.1.0]: https://github.com/ur-stack/urauth/releases/tag/urauth-py-v0.1.0
