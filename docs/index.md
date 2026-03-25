---
layout: home

hero:
  name: urauth
  text: Unified Auth for Python & TypeScript
  tagline: JWT, OAuth2, RBAC, Zanzibar relations, and hierarchical multi-tenancy. One design, every runtime.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/grandmagus/urauth

features:
  - title: Python + FastAPI
    details: Full-featured auth backend with FastAPI adapter, token lifecycle, session management, and OAuth2 providers.
    link: /packages/py/
  - title: TypeScript Core
    details: Zero-dependency shared core — permissions, roles, relations, and multi-tenant hierarchy for any JS runtime.
    link: /packages/ts/
  - title: Multi-Framework
    details: First-class middleware for Node.js, Hono, Express, Fastify, H3/Nitro, Vue composables, and Nuxt module.
    link: /guide/
  - title: Composable Permissions
    details: "Separator-agnostic permission format with wildcard support. Compose requirements with .and() / .or() operators."
    link: /guide/concepts
  - title: Zanzibar Relations
    details: Google Zanzibar-style relation tuples for fine-grained, object-level authorization.
    link: /guide/concepts#relations
  - title: Hierarchical Multi-Tenancy
    details: "TenantPath carries full hierarchy context through tokens — organization > region > team."
    link: /guide/concepts#multi-tenancy
---
