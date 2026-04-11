# Integrations

urauth is not a Python library with a JavaScript afterthought. It provides idiomatic, first-class packages for every major platform in the stack — each one designed to feel natural in that ecosystem rather than porting Python patterns directly.

## Supported Platforms

| Package | Language / Runtime | Status |
|---|---|---|
| `urauth` | Python 3.10+ | Stable |
| `@urauth/ts` | TypeScript (any runtime) | Stable |
| `@urauth/react` | React 18+ | Stable |
| `@urauth/vue` | Vue 3 | Stable |
| `@urauth/nuxt` | Nuxt 3 | Stable |
| `@urauth/next` | Next.js 14+ (App Router) | Stable |
| `@urauth/node` | Node.js 18+ | Stable |
| `@urauth/express` | Express 4+ | Stable |
| `@urauth/fastify` | Fastify 4+ | Stable |
| `@urauth/hono` | Hono 4+ | Stable |
| `@urauth/h3` | H3 / Nitro | Stable |
| `urauth-dotnet` | .NET / C# | Planned |

The shared security model — token formats, permission semantics, tenant hierarchy — is consistent across all packages. A token issued by the Python backend is directly readable by `@urauth/ts` without any translation layer.

**.NET / C# support** is on the roadmap. The core design (JWT lifecycle, RBAC, multi-tenant) maps cleanly to ASP.NET Core middleware conventions. Community contributions are welcome.

## Backend

### Python — `urauth`

Full-featured auth backend with FastAPI adapter, token lifecycle, session management, and OAuth2 providers. See the [Python package docs](/packages/py/).

### Node.js — `@urauth/node`

Backend SDK for Node.js runtimes. Handles JWT issuance and verification, token stores, and the full token lifecycle. See the [Node.js package docs](/packages/node/).

## Middleware

Each middleware package wraps `@urauth/node` and exposes framework-idiomatic APIs for route protection.

### Hono — `@urauth/hono`

Hono middleware for edge and serverless runtimes. See the [Hono package docs](/packages/hono/).

### Express — `@urauth/express`

Express middleware for traditional Node.js servers. See the [Express package docs](/packages/express/).

### Fastify — `@urauth/fastify`

Fastify plugin with full lifecycle hooks. See the [Fastify package docs](/packages/fastify/).

### H3 / Nitro — `@urauth/h3`

H3 middleware for Nuxt server routes and Nitro-based backends. See the [H3 package docs](/packages/h3/).

## Frontend

### TypeScript Core — `@urauth/ts`

Zero-dependency shared types, permission primitives, and authorization helpers for any JS runtime. See the [TypeScript package docs](/packages/ts/).

### React — `@urauth/react`

React hooks and context provider for auth state management. See the [React package docs](/packages/react/).

### Vue — `@urauth/vue`

Vue composables for reactive auth state. See the [Vue package docs](/packages/vue/).

### Nuxt — `@urauth/nuxt`

Nuxt module with auto-imports and SSR-aware auth state. See the [Nuxt package docs](/packages/nuxt/).

### Next.js — `@urauth/next`

Next.js App Router integration with server components and middleware support. See the [Next.js package docs](/packages/next/).
