# Overview

**urauth** is a unified authentication and authorization library spanning Python and TypeScript. It provides a consistent security model across backend and frontend, with shared concepts and compatible token formats.

## Architecture

```
                        urauth monorepo
  ┌──────────────────────────────────────────────────┐
  │                                                  │
  │  Python                    TypeScript            │
  │  ┌──────────┐              ┌──────────┐          │
  │  │  urauth   │              │ @urauth/ │          │
  │  │  (core)   │              │   ts     │          │
  │  └────┬─────┘              └────┬─────┘          │
  │       │                         │                │
  │  ┌────┴─────┐         ┌────────┼────────┐       │
  │  │ FastAPI   │         │        │        │       │
  │  │ adapter   │    @urauth/   @urauth/  @urauth/  │
  │  └──────────┘      node       vue      nuxt     │
  │                      │                           │
  │              ┌───────┼───────┐                   │
  │           @urauth/ @urauth/ @urauth/ @urauth/    │
  │            hono   express  fastify     h3        │
  └──────────────────────────────────────────────────┘
```

## Packages

| Package | Runtime | Description |
|---------|---------|-------------|
| [urauth](/packages/py/) | Python 3.10+ | Core library with FastAPI adapter |
| [@urauth/ts](/packages/ts/) | Any JS | Shared TypeScript types, permissions, and authorization |
| [@urauth/node](/packages/node/) | Node.js 18+ | Backend SDK — JWT, token lifecycle, stores |
| [@urauth/hono](/packages/hono/) | Hono 4+ | Hono middleware |
| [@urauth/express](/packages/express/) | Express 4+ | Express middleware |
| [@urauth/fastify](/packages/fastify/) | Fastify 4+ | Fastify plugin |
| [@urauth/h3](/packages/h3/) | H3 / Nitro | H3 middleware (Nuxt server routes) |
| [@urauth/vue](/packages/vue/) | Vue 3 | Vue composables for auth state |
| [@urauth/nuxt](/packages/nuxt/) | Nuxt 3 | Nuxt module with auto-imports |

## Design Principles

- **Protocol-based** — Implement store interfaces against your database; no vendor lock-in.
- **Composable** — Permissions, roles, and relations compose with `.and()` / `.or()` operators.
- **Separator-agnostic** — `"user:read"` and `"user.read"` are semantically equal across all packages.
- **Hierarchical tenancy** — `TenantPath` carries full hierarchy through JWT claims, not just a flat ID.
- **Python-authoritative** — The Python package defines the canonical API; TypeScript stays in sync.
