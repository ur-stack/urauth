# Auth Python — Architecture

> **Legend**
> - `simple` — thin wrapper or pass-through; minimal urauth logic
> - `[ext]` — external / 3rd-party library (delegated)
> - `[policy]` — policy-account boundary (tenant / permission scope)
> - **`urauth`** — urauth-owned logic

---

## Identity & Auth

| Password | OTP / TOTP | Magic link / token | Passkey / WebAuthn |
|---|---|---|---|
| `simple` — oauth2, jwt, email | **urauth-otp** | **urauth-magic** | **urauth-passkey** |

```
Account merge ──────────────────────────────────────────► urauth
```

---

## OAuth 2.0 / OIDC

| OAuth2 lib | Credentials | Linked identities | Devices |
|---|---|---|---|
| `[ext]` authlib | `simple` — trade, type, scopes | **urauth** — provider, sub, reason, scope | `simple` — registration, fingerprint |

---

## Session & JWT Management

| Session store | JWT factory | Token rotation | Association |
|---|---|---|---|
| `[ext]` redis / memcache / DB | **urauth-core** | **urauth-core** | **urauth-core** — user / device / org link |

---

## MFA & Step-Up

| TOTP | SMS / email OTP | Backup codes | Step-up auth |
|---|---|---|---|
| **urauth-otp** | **urauth-otp** | **urauth-otp** | **urauth-core** |

---

## Access Control

| RBAC | ABAC | Relation types | Guard combinators |
|---|---|---|---|
| **urauth-rbac** | **urauth-abac** | `[policy]` — owner, member, viewer | **urauth** — `relation_type`, `claims_check` |

---

## Client & API Key Management

| OAuth clients | API keys | Scopes | Service accounts |
|---|---|---|---|
| **urauth-oauth2** — client_id, secret, redirect | **urauth-apikey** — prefix, hash, expiry | **urauth** — resource, action | **urauth** |

---

## Crypto Primitives

| Algorithms | Key formats | Storage | Headers & JWS |
|---|---|---|---|
| `[ext]` jwt, cryptography — RS256, ES256, HS256 | `[ext]` — RSA, EC, oct | `simple` — PEM, JWK | `simple` — kid, alg, use |

---

## Token Lifecycle

| JWT / JWTFactory | Refresh rotation | Invalidation cache | Session cache |
|---|---|---|---|
| **urauth-core** — iss, sub, aud, jti, exp | **urauth-core** | `[ext]` redis / memcache — cachetools | `[ext]` |

---

## Account Lifecycle

| Email / password reset | Suspend / ban | Deletion / GDPR |
|---|---|---|
| **urauth** | **urauth** | **urauth** |

---

## Audit & Security Events

| Audit log | Anomaly detection | Breach detection | Event webhooks |
|---|---|---|---|
| **urauth** — structlog, DB | **urauth** | **urauth** | **urauth** |

---

## Multi-Tenancy

| Tenants | Membership | Tenant quotas | Custom SSO |
|---|---|---|---|
| `[policy]` **urauth-tenancy** | `[policy]` **urauth-tenancy** | `[policy]` **urauth-tenancy** | **urauth-sso** |

---

## Extensibility

| Auth base | Event hooks | Claims enrichment | Storage adaptors |
|---|---|---|---|
| **urauth-core** | **urauth** | **urauth** | **urauth** |

---

## Core Extension Points

`urauth.Auth` exposes the following configurable slots:

```
urauth.Auth
├── event_handlers      — lifecycle hooks (on_login, on_logout, on_token_refresh, …)
├── claims              — claims enrichment pipeline
├── jwt / password      — pluggable JWT factory and password hasher
├── email               — email transport adapter
├── config / settings   — local config layer
├── storage             — storage backend adaptor
├── router              — FastAPI router integration
└── custom_sso          — bring-your-own SSO provider
```

> `itsdangerous` is used internally for signing. Everything else is a configured wrapper — no magic, no hidden globals.
