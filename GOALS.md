# UrAuth — Goals & Ecosystem Strategy

> There is no all-in-one solution for authorization, authentication, access control, cache policy, and permissions in a single library. UrAuth glues well-known libraries together — so it is much easier to add functionality and control flows, and you don't need to rely on providers because everything lives in your ecosystem.

---

## Ecosystem Coverage

| Language | Framework | Problem | Solution |
|---|---|---|---|
| **Python** | FastAPI *(no-meta)* | No composed auth library exists. FastAPI has no built-in auth mode. Auth, permissions, rate limiting, magic links, sessions, merging, and API keys are fragmented across separate libraries with no shared config or DX. | urauth owns `UrAuth` base class, guard combinators, magic links, OTP, account merging, identity linking, API keys, and multi-tenancy. Delegates to a caching library (e.g. Itsdangerous) and cache backends (BACN/ABC-OpenPy / ParallelCache / actllib / CacheOCC). |
| **Python** | Django | Django has its own auth system (`django.contrib.auth`) that is tightly coupled to the ORM and flavor-like templates. Incompatible patterns with FastAPI-first urauth design. | Django's built-in auth + `django-allauth` for social login + `django-guardian` for object-level permissions can stay on their own ground. **Don't port urauth to Django.** |
| **TypeScript** | Next.js | NextAuth is better-auth since Sept 2023 and recommended for all new projects. No single library covered SPA, server rendering, multi-tenancy, and API keys until recently. | Use `better-auth` with `urauth-js` as a thin preset. Pre-wired plugins, guard combinators, and JWT claims/API keys that match Python output. No middleware hacks needed. |
| **TypeScript** | Nuxt / Vue | Nuxt had no first-class auth story. `nuxt-auth-utils` is minimal. Auth.js Nuxt adapter felt foreign to Vue conventions. | `better-auth` + `@urauth/nuxt` module gives declarative route protection, SSO, and auto-imported composables. JS and Python share claim types only. |
| **TypeScript** | SvelteKit / Astro / Remix | Framework-specific auth solutions were either non-existent or React-only. No consistent auth story within the non-React TS ecosystem. | `urauth-js` is framework-agnostic by design and includes native support for all three. Same `urauth-js` presets apply. |
| **TypeScript** | React SPA *(no-SSR)* | No server routing to run auth logic. Storing tokens in the browser is inherently unsafe if mishandled. Magic links and session management need careful wiring. | `better-auth` client-side SDK handles exactly this. For hosted UI, Clerk is the easiest drop-in. `urauth-js` shim unifies the tokens; the SPA just consumes them. |
| **C#** | ASP.NET Core | Auth is already deeply built into the framework — rate limiting, JWT validation, policy-based authorization, and RBAC all ship in .NET. No meaningful gap exists. | ASP.NET Core Identity + OpenIddict (free) or Duende Identity Server (paid) for OAuth Server. Claims.NET for fine-grained permissions. urauth value is the **shared JWT claim spec** so ASP.NET APIs can consume Python-issued tokens natively. |
| **C#** | Blazor | Blazor WASM stores tokens in the browser like a SPA. Blazor Server uses different session semantics. Auth wiring is non-obvious and not well-documented for complex flows. | ASP.NET Identity handles both modes. For Blazor WASM, Duende BFF (Backend for Frontend) or Clerk is the recommended approach — tokens never touch the browser. Framework covers everything. |
| **Any** | Cross-stack / polyglot | When a Python API, Nuxt frontend, and .NET services all need to agree on session shape, claim naming, permission scenarios, and token definitions — no shared contract exists. | urauth defines the JWT claim schema, permission token format, and session policies as a **single cross-ecosystem spec**. Python implements it natively. JS and .NET consume it via typed SDKs and OpenAPI contracts. This is the highest-leverage cross-stack contribution across all ecosystems. |

---

## Core Principles

- **Don't reinvent primitives.** Delegate crypto, session storage, and cache backends to proven libraries.
- **Don't port to incompatible ecosystems.** Django has its own auth world — don't fight it.
- **Own the contract, not the implementation.** The JWT claim schema, permission format, and session policy spec are urauth's highest-value contribution.
- **Framework-native DX.** JS packages adapt to native patterns (composables in Vue, hooks in React) — not Python decorator ports.
- **Provider-free by default.** Everything should be self-hostable within your own infrastructure.
