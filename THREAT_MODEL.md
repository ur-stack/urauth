# Threat Model — urauth

## 1. System Overview

urauth is a multi-language authentication and authorization library (Python + TypeScript) providing:

- JWT token creation, verification, refresh with rotation
- Session management (in-memory, Redis)
- RBAC with role hierarchies and Zanzibar-style relation tuples
- Framework adapters (FastAPI, Express, Fastify, H3, Hono, Vue, Nuxt)
- OAuth2/OIDC client integration
- Multi-tenant support with hierarchical permissions

## 2. Assets (What We Protect)

| Asset | Sensitivity | Notes |
|-------|------------|-------|
| JWT signing keys | **Critical** | Compromise = full token forgery |
| User credentials (password hashes) | **Critical** | Stored by consumer app, hashed by urauth |
| Access tokens | **High** | Short-lived, grant API access |
| Refresh tokens | **High** | Long-lived, grant new access tokens |
| Session state | **High** | Tied to user identity |
| CSRF tokens | **Medium** | Prevents cross-site request forgery |
| Role/permission definitions | **Medium** | Misconfiguration = privilege escalation |
| OAuth2 client secrets | **Critical** | Compromise = impersonation via provider |
| PKCE verifiers/state params | **High** | Prevents OAuth2 interception attacks |

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│  External (untrusted)                           │
│  - HTTP requests, headers, cookies              │
│  - JWT tokens from client                       │
│  - OAuth2 callback parameters                   │
│  - User-supplied credentials                    │
│  - Request path/query parameters                │
├─────────────────────────────────────────────────┤
│  Framework adapter boundary                     │
│  - Token extraction (bearer/cookie/header)      │
│  - CSRF validation                              │
│  - Request → AuthContext resolution              │
├─────────────────────────────────────────────────┤
│  Core library boundary                          │
│  - JWT sign/verify (PyJWT / jose)               │
│  - Token lifecycle (issue/refresh/revoke)       │
│  - Password hashing (bcrypt)                    │
│  - AuthContext + permission checking             │
│  - Role registry + hierarchy expansion           │
├─────────────────────────────────────────────────┤
│  Storage boundary                               │
│  - TokenStore (revocation tracking)             │
│  - SessionStore (session state)                 │
│  - RoleCache (role definitions)                 │
│  - External DB (user records — consumer app)    │
│  - Redis (sessions, optional)                   │
└─────────────────────────────────────────────────┘
```

## 4. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **Unauthenticated attacker** | Sends arbitrary HTTP requests | Gain access without credentials |
| **Authenticated low-privilege user** | Has valid tokens, limited permissions | Escalate privileges, access other users' data |
| **Token thief** | Has stolen access or refresh token | Impersonate victim, persist access |
| **Network attacker (MITM)** | Can intercept/modify traffic (no TLS) | Steal tokens, session hijack |
| **XSS attacker** | Can execute JS in victim's browser | Steal tokens from cookies/storage, CSRF bypass |
| **Misconfiguring developer** | Uses the library with unsafe defaults | Accidentally deploy insecure configuration |
| **Cache/store attacker** | Can read/write to Redis or cache | Poison role definitions, forge sessions |

## 5. Threats and Mitigations

### T1: Token Forgery

**Attack**: Craft a JWT with arbitrary claims without the signing key.

| Control | Status |
|---------|--------|
| HMAC signature verification via PyJWT/jose | Implemented |
| Algorithm pinned in config (no `alg` header trust) | Implemented |
| `none` algorithm rejected | Implemented (PyJWT/jose default) |
| Minimum secret key length enforced (32 chars HMAC) | Implemented |
| Weak secret detection | Implemented |
| Reserved claims protected from extra_claims override | Implemented |

**Residual risk**: Algorithm confusion if consumer misconfigures asymmetric/symmetric keys.

### T2: Token Replay / Theft

**Attack**: Reuse a stolen access or refresh token.

| Control | Status |
|---------|--------|
| Short access token TTL (configurable) | Implemented |
| Refresh token rotation (new token on each refresh) | Implemented |
| Refresh token reuse detection (family revocation) | Implemented |
| Token revocation via TokenStore | Implemented |
| Revoke-all-for-user capability | Implemented |
| JTI uniqueness (UUID4) | Implemented |

**Residual risk**: Access token valid until expiry even after revocation (stateless JWT limitation). Mitigated by short TTL.

### T3: Session Attacks

**Attack**: Fixation, hijacking, or replay of sessions.

| Control | Status |
|---------|--------|
| Server-generated session IDs (UUID4) | Implemented |
| Session expiration (TTL) | Implemented |
| Session deletion on logout | Implemented |
| Family-based session tracking | Implemented |
| Redis session store with TTL | Implemented |

**Residual risk**: In-memory store loses revocation state on restart. Race conditions during concurrent refresh.

### T4: CSRF

**Attack**: Forge requests from another origin using victim's cookies.

| Control | Status |
|---------|--------|
| Double-submit cookie pattern | Implemented |
| `hmac.compare_digest()` for constant-time comparison | Implemented |
| SameSite=Lax cookie default | Implemented |
| CSRF middleware for unsafe methods | Implemented |

**Residual risk**: CSRF cookie must be readable by JS (`httponly=False`) — increases XSS attack surface.

### T5: Privilege Escalation

**Attack**: Manipulate permissions/roles to gain unauthorized access.

| Control | Status |
|---------|--------|
| Server-side permission resolution (not from token alone) | Implemented |
| Role hierarchy with cycle detection (Python) | Implemented |
| Wildcard permission matching with defined semantics | Implemented |
| Composable requirements (AND/OR) | Implemented |
| Tenant-scoped permissions | Implemented |

**Residual risk**: Role hierarchy cycle detection missing in TypeScript (stack overflow). Extra claims in JWT not validated beyond reserved list.

### T6: Configuration Misuse

**Attack**: Developer deploys with insecure settings.

| Control | Status |
|---------|--------|
| Production mode rejects default/weak keys | Implemented |
| Minimum key length enforcement | Implemented |
| Weak secret blocklist | Implemented |
| Secure cookie defaults (httponly, secure, samesite) | Implemented |
| Testing mode explicit opt-in for insecure keys | Implemented |

**Residual risk**: No validation of TTL values (could be 0 or negative). No algorithm string validation. No secret rotation support without restart.

### T7: OAuth2 Interception

**Attack**: Intercept OAuth2 authorization code or redirect.

| Control | Status |
|---------|--------|
| PKCE (S256) implementation | Implemented |
| State parameter generation | Implemented |
| `secrets.token_urlsafe()` for random values | Implemented |

**Residual risk**: State validation is caller's responsibility — not enforced by library. OIDC metadata cached indefinitely (no expiration).

### T8: Malformed Input

**Attack**: Send garbage/oversized/unicode tokens or claims to crash or bypass.

| Control | Status |
|---------|--------|
| PyJWT/jose handle malformed JWT gracefully | Implemented |
| Hypothesis fuzz tests for token parsing (Python) | Implemented |
| Error mapping (no raw exceptions to client) | Implemented |

**Residual risk**: No input size limits on tokens. No fuzz testing for TypeScript. Relation tuple parsing has edge cases with unusual separators.

### T9: Cache/Store Poisoning

**Attack**: Compromise Redis or cache to inject forged roles/sessions.

| Control | Status |
|---------|--------|
| Static roles override loaded/cached roles | Implemented |
| Role loader + cache separation | Implemented |

**Residual risk**: No schema validation on cached role data. Redis session data stored as plaintext JSON. No encryption at rest for session store.

## 6. Forbidden Outcomes

These must **never** happen regardless of input:

1. An unsigned or incorrectly signed token is accepted as valid
2. An expired token grants access
3. A revoked refresh token produces new valid tokens (without family revocation)
4. A user with no permissions passes a permission check
5. A forged CSRF token passes validation
6. A password hash is reversible or uses weak algorithm
7. A crashed/panicked auth check defaults to "allow"
8. Sensitive error details (keys, hashes, internal state) leak to HTTP responses
9. A developer using documented defaults deploys an insecure configuration
10. Role hierarchy cycles cause infinite loops or stack overflows

## 7. Testing Strategy

| Layer | What | Where |
|-------|------|-------|
| **Negative unit tests** | Every forbidden outcome above | `tests/security/` |
| **Abuse-case integration tests** | Forged requests against sample app | `tests/integration/` |
| **Fuzz testing** | Token parsers, cookie decoders, claim objects | `tests/fuzz/` |
| **Property-based tests** | Mutation of signed tokens always fails, expiry always enforced | `tests/security/` |
| **Config misuse tests** | Weak secrets, missing issuer, disabled expiry | `tests/security/misconfiguration/` |
| **Static analysis** | Bandit (Python), type checking | CI pipeline |
| **Dependency scanning** | pip-audit, npm audit | CI pipeline |
| **Secret scanning** | detect-secrets | CI pipeline |
