# Tutorial

This tutorial walks you through every major feature of **fastapi-auth**, building on top of each previous step.

By the end, you'll have a fully-featured auth system with password login, refresh tokens, OAuth2 social login, role-based access control, and multi-tenant support.

## What You'll Build

| Page | What you'll learn |
|------|-------------------|
| [First Steps](first-steps.md) | Install, create a user model, implement a backend, wire up auth |
| [Protecting Routes](protecting-routes.md) | `current_user()`, scopes, roles, freshness checks |
| [Refresh Tokens](refresh-tokens.md) | Token rotation, reuse detection, logout |
| [OAuth2 & Social Login](oauth2-social-login.md) | Google, GitHub, and other providers |
| [RBAC & Permissions](rbac-permissions.md) | Role hierarchies, wildcard permissions |
| [Multi-Tenant](multi-tenant.md) | Tenant resolution from JWT, headers, paths, subdomains |

!!! tip
    Each page is self-contained with runnable code. Start from the beginning if this is your first time, or jump to the topic you need.
