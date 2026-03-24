# Tutorial

This tutorial walks you through every major feature of **urauth**, building on top of each previous step.

By the end, you will have a fully-featured auth system with password login, guards, access control, refresh tokens, OAuth2 social login, role-based access control, Zanzibar-style relations, and multi-tenant support.

## What You'll Build

A SaaS task manager with complete authentication and authorization. Each page introduces a new concept and builds on the previous one.

| Page | What you'll learn |
|------|-------------------|
| [First Steps](first-steps.md) | Install, create a user model, subclass `Auth`, wire up `FastAuth`, test with curl |
| [Protecting Routes](protecting-routes.md) | `current_user`, `context`, optional auth, `AuthContext` introspection |
| [Guards & Requirements](guards.md) | Composable `Permission`, `Role`, `Relation` primitives with `&`/`|`, dual-use guards |
| [Access Control](access-control.md) | `RoleRegistry`, `PermissionEnum`, checker-based `access.guard()`, inline checks |
| [Refresh Tokens](refresh-tokens.md) | Token rotation, reuse detection, logout, logout-all |
| [Pipeline](pipeline.md) | Declarative `Pipeline` config, `auto_router()`, strategy selection |
| [OAuth2 & Social Login](oauth2-social-login.md) | Google, GitHub, and other providers via `OAuthLogin` |
| [RBAC & Permissions](rbac-permissions.md) | Role hierarchies, wildcard permissions, `RoleExpandingChecker` |
| [Relations](relations.md) | Zanzibar-style `Relation` primitives, `require_relation`, `check_relation` |
| [Multi-Tenant](multi-tenant.md) | Tenant resolution from JWT claims, headers, scoped permissions |

!!! tip
    Each page is self-contained with runnable code. Start from the beginning if this is your first time, or jump to the topic you need.

## Prerequisites

- Python 3.10+
- Familiarity with [FastAPI](https://fastapi.tiangolo.com/) basics (routes, dependencies, `Depends`)
- A terminal and a text editor

## Running the Examples

Every code example in this tutorial can be saved to a file (e.g., `app.py`) and run with:

```bash
uvicorn app:app --reload
```

Then test with `curl` or open `http://localhost:8000/docs` to use the interactive Swagger UI.
