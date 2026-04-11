# Overview

**urauth** is a unified authentication and authorization library spanning Python and TypeScript. It provides a single, composable security layer that is secure by default, easy to test, and straightforward to extend — without requiring deep expertise in cryptographic protocols or token lifecycle management.

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
| [@urauth/react](/packages/react/) | React 18+ | React hooks for auth state |
| [@urauth/next](/packages/next/) | Next.js 14+ | Next.js App Router integration |

## Design Principles

- **Protocol-based** — Implement store interfaces against your database; no vendor lock-in.
- **Composable** — Permissions, roles, and relations compose with `&` / `|` operators.
- **Separator-agnostic** — `"user:read"` and `"user.read"` are semantically equal across all packages.
- **Hierarchical tenancy** — `TenantPath` carries full hierarchy through JWT claims, not just a flat ID.
- **Python-authoritative** — The Python package defines the canonical API; TypeScript stays in sync.
- **Secure by default** — Every default is the safe choice. Weakening requires an explicit, deliberate override.

---

This page also covers the security practices baked into urauth, how the codebase is maintained, and what happens when a vulnerability is found.

---

## Native Language Support

urauth is not a Python library with a JavaScript afterthought. It provides idiomatic, first-class packages for every major platform in the stack — each one designed to feel natural in that ecosystem rather than porting Python patterns directly.

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

---

## What urauth Does

Authentication and authorization are solved problems with well-understood patterns — but most frameworks either leave them entirely to the developer or provide solutions that are hard to extend, hard to test, or insecure by default. urauth occupies the space in between: it handles the common 90% with safe defaults, and exposes every extension point as a clean protocol so you can replace any part of it.

### Core capabilities

| Capability | What you get |
|---|---|
| **JWT lifecycle** | Issue, validate, rotate, and revoke access + refresh token pairs. Configurable TTL, family-based reuse detection, pluggable token stores. |
| **Password authentication** | bcrypt hashing (12 rounds), constant-time comparison, configurable cost factor. |
| **OAuth2 / social login** | Google, GitHub, Microsoft, Apple, Discord, GitLab — add social login with a single provider config. Magic link and OTP methods included. |
| **RBAC + permissions** | `RoleRegistry` with permission inheritance and wildcard matching (`task:*`, `billing:read`). `PermissionEnum` for type-safe definitions. |
| **Composable guards** | `Permission`, `Role`, and `Relation` primitives compose with `&` (AND) and `|` (OR). Guards work as `@decorator` and `Depends()` interchangeably. |
| **Multi-tenant isolation** | Flat or hierarchical tenants. Tenant resolution from JWT claims, headers, paths, or subdomains. Cascading permissions, default role provisioning. |
| **Pluggable transports** | Bearer header, HTTP-only cookie, or hybrid. Swap transports without changing application code. |
| **Rate limiting** | Built-in `RateLimiter` with pluggable key strategies for brute-force protection. |
| **Protocol-based** | Every extension point (`TokenStore`, `SessionStore`, `PermissionChecker`, `UserProtocol`) is a Python `Protocol` — no base class inheritance, no vendor lock-in. |

### What urauth is not

urauth does not protect against compromised infrastructure (stolen signing key, misconfigured TLS, SQL injection in your application). It assumes HTTPS is in place, handles the cryptographic identity layer, and stops there. See the [Threat Model](/packages/py/best-practices/threat-model) for a precise statement of scope.

---

## Security Practices

### Secure defaults

urauth ships with defaults that are safe out of the box. Weakening them requires an explicit, deliberate override.

| Default | Effect |
|---|---|
| `cookie_httponly=True` | Tokens in cookies are inaccessible to JavaScript — XSS cannot steal them. |
| `cookie_secure=True` | Cookies are only sent over HTTPS. |
| `cookie_samesite="lax"` | Blocks cross-origin POST requests with cookies by default. |
| Algorithm pinned to `HS256` | Prevents algorithm confusion attacks (`alg: none`, RS/HS substitution). `"none"` is never in the allowed list. |
| Reserved claim protection | `sub`, `exp`, `iat`, `jti`, `iss`, `aud`, `type` cannot be overwritten via `extra_claims`. |
| Fail-closed token store | If the store is unreachable, tokens are rejected — not silently accepted. |
| Refresh token rotation | Every refresh issues a new pair and immediately revokes the old token. |
| Weak key blocklist | Common weak secrets (`"secret"`, `"password"`, `"changeme"`, etc.) are rejected at startup. |
| Minimum key length (32 chars) | HMAC keys shorter than 32 characters raise `ValueError` at startup. |

### No custom cryptography

All cryptographic operations are delegated to audited, widely-deployed libraries:

- **JWT signing and verification** — [PyJWT](https://pyjwt.readthedocs.io/) (100M+ downloads/month), which uses Python's `hmac.compare_digest` for constant-time HMAC verification.
- **Password hashing** — [bcrypt](https://pypi.org/project/bcrypt/) (50M+ downloads/month), a thin wrapper around the OpenBSD bcrypt C implementation.

urauth does not implement any custom cryptographic primitives. Token format is standard JWT (RFC 7519). There are no novel constructions.

### Authentication security recommendations

These are the practices applied inside urauth and recommended for applications built on top of it.

**Token management**

- Use short-lived access tokens (5–15 minutes) paired with refresh token rotation. A leaked access token expires quickly; a leaked refresh token can only be used once before the family is revoked.
- Set `token_issuer` and `token_audience` in production. Tokens issued by one service must not be accepted by another.
- Use a persistent, shared token store (Redis) in production. `MemoryTokenStore` is for development only — it loses all tokens on restart and cannot be shared across workers.

**Secret key management**

- Generate a cryptographically random secret of at least 32 bytes: `openssl rand -hex 32`.
- Load it from an environment variable (`AUTH_SECRET_KEY`) or a secrets manager (Vault, AWS Secrets Manager). Never hardcode it.
- `allow_insecure_key=True` is for test fixtures only. It must never appear in production configuration.

**Cookie-based authentication**

- Enable CSRF protection whenever you use cookie transport for state-changing requests (`AUTH_CSRF_ENABLED=true`). The double-submit cookie pattern is built in.
- Bearer tokens in the `Authorization` header do not need CSRF protection — browsers do not attach custom headers cross-origin.
- Never store tokens in `localStorage`. Use `httpOnly` cookies (the urauth default) or, for SPAs that must use Bearer tokens, store them in memory — not in Web Storage.

**Extra claims**

- Never pass unvalidated user input as `extra_claims`. Reserved claims are protected, but application-level claims like `role` or `is_admin` can be injected if you pass `request.json()` directly.
- Always use a controlled allowlist derived from your application logic.

**Access control**

- Apply `TenantGuard` on every route that must be tenant-isolated. There is no global enforcement — opt-out is not possible because each route must opt in. Consider a startup audit of route coverage.
- Assign the `"*"` wildcard permission only to the highest-trust administrative roles. It matches every permission check in the system.
- Test both the authorized and denied paths for every guarded endpoint. A missing guard is invisible to urauth.

---

## Code Maintenance

### Continuous integration

Every pull request must pass all of the following checks before merge:

| Check | Tool | What it catches |
|---|---|---|
| Linting | `ruff` | Style violations, unused imports, common bug patterns |
| Type checking | `basedpyright` (strict mode) | Type errors, missing annotations, unsafe casts |
| Tests | `pytest` on Python 3.10, 3.11, 3.12, 3.13 | Regressions across all supported Python versions |
| Dependency scanning | `pip-audit` | Known CVEs in transitive dependencies |
| Static analysis | `bandit` | Common security anti-patterns in Python code |
| Secret scanning | `detect-secrets` | Credentials accidentally committed to source |

There is no mechanism to skip these checks. `--no-verify` bypasses are not permitted.

### Minimal dependencies

urauth has exactly four core runtime dependencies:

| Dependency | Purpose |
|---|---|
| `pydantic` | Config and data validation |
| `pydantic-settings` | Environment-based configuration |
| `PyJWT` | JWT encode/decode |
| `bcrypt` | Password hashing |

Smaller dependency surface means fewer CVEs to track and fewer transitive supply-chain risks. Optional extras (`fastapi`, `oauth`, `redis`, `sqlalchemy`) are not installed unless the application explicitly requests them.

### Versioning and changelog

urauth follows [semantic versioning](https://semver.org/). Breaking changes only in major versions. Every release includes a changelog entry generated from commit history. Supported version ranges are listed in `SECURITY.md`.

---

## Testing

### Test structure

Tests are organized into three layers:

```
tests/
  unit/                          # Fast, isolated, no I/O
    test_vulnerability_regression.py   # Known vulnerability patterns that must never reappear
    test_tokens_security.py            # Token forgery, tampering, replay
    test_refresh_security.py           # Refresh rotation, reuse detection, store failure
    ... (43 more unit test files)
  integration/                   # Full request/response cycles with a real FastAPI app
  fuzz/                          # Hypothesis property-based and fuzz tests
```

### Coverage

The coverage threshold is **85%**, enforced in CI. Builds fail if coverage drops below this floor. Run locally with:

```bash
make test-cov
```

Coverage is measured on `src/urauth/` only. Framework-specific adapters (`contrib/`, `sessions/redis.py`) and example code are excluded from the threshold.

### Security-specific test suites

Three test files are dedicated exclusively to security regression testing:

- **`tests/unit/test_vulnerability_regression.py`** — a running catalogue of known vulnerability patterns (algorithm confusion, claim injection, token replay, etc.) that must never reappear. Each test is written when a class of vulnerability is identified, even if it was never exploited.
- **`tests/unit/test_tokens_security.py`** — exhaustive tests for token forgery, header tampering, payload manipulation, and signature stripping.
- **`tests/unit/test_refresh_security.py`** — tests for refresh token rotation correctness, reuse detection triggering family-wide revocation, and store-failure fail-closed behavior.

### Fuzz and property-based testing

urauth uses [Hypothesis](https://hypothesis.readthedocs.io/) for property-based testing. Key invariants tested:

- Any mutation of a signed token must fail verification.
- Any token whose `exp` claim is in the past must be rejected.
- Any token with an algorithm not in the allowed list must be rejected.
- Refresh token reuse must always trigger family revocation, regardless of timing.

### Testing your application

urauth provides first-class test utilities:

```python
from urauth.testing import create_test_token, AuthOverride

# Unit test — create a signed token directly, skip the login endpoint
token = create_test_token(user_id="u1", roles=["admin"], secret_key="test-secret")

# Integration test — override auth context to test authorization logic
with AuthOverride(auth, user_id="u1", roles=["viewer"]):
    response = client.delete("/admin/users/1")
    assert response.status_code == 403
```

See [Testing How-To](/packages/py/how-to/testing) and [Testing Best Practices](/packages/py/best-practices/testing) for full examples including tenant isolation and permission boundary testing.

---

## Vulnerability Response

### Reporting

**Do not report security vulnerabilities through public GitHub issues.** Public disclosure before a fix is available puts every application using urauth at risk.

Use [GitHub Security Advisories](https://github.com/ur-stack/urauth/security/advisories/new) to report privately. Include:

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Impact assessment (what can an attacker achieve?)
- Affected versions
- Suggested fix, if you have one

### Response timeline

urauth is an independent open-source project maintained without commercial sponsorship. Response times are best-effort and bounded by maintainer availability, but we treat security reports as the highest priority.

| Stage | Target |
|---|---|
| Acknowledgment | Within 48 hours of report |
| Initial assessment | Within 5 business days |
| Fix for critical vulnerabilities | 24 hours to 7 days after confirmed vulnerability |
| Fix for non-critical vulnerabilities | Up to 30 days |

::: warning Response time and sponsorship
Fix turnaround for critical issues is typically 24–48 hours, but may extend up to 7 days depending on complexity and maintainer availability. We are not backed by a security team or commercial sponsor. If your organization requires guaranteed SLA-backed response times, consider sponsoring the project or contributing a fix directly.
:::

### What we monitor

- **GitHub Dependabot / security alerts** — all dependency vulnerabilities are tracked automatically. We update affected dependencies promptly on notification.
- **`pip-audit` in CI** — every build scans for known CVEs in the dependency tree. A build that introduces a CVE-bearing dependency fails before merge.
- **Manual triage** — new CVEs in `PyJWT`, `bcrypt`, `pydantic`, and `pydantic-settings` are reviewed as they are published.

### What is in scope

| In scope | Out of scope |
|---|---|
| Authentication bypass | Denial of service (unless caused by a small input) |
| Token forgery or manipulation | Issues requiring physical server access |
| Secret key leakage | Social engineering |
| Privilege escalation | Issues in dependencies (report upstream; we update promptly) |
| Injection vulnerabilities | Misconfiguration by the user (but suggestions to make it harder are welcome) |
| Cryptographic weaknesses | |
| Cross-tenant data access | |

### Disclosure process

We follow coordinated disclosure:

1. Reporter submits vulnerability privately via GitHub Security Advisories.
2. We acknowledge within 48 hours and confirm scope.
3. We develop and test a fix, keeping the reporter informed.
4. We release the fix with a patch version bump and publish a GitHub Security Advisory.
5. Reporter is credited in the advisory and CHANGELOG unless they request anonymity.

We will not take legal action against researchers who act in good faith.

### Maturity level

urauth is pre-1.0 software. Here is an honest assessment of where it stands:

| Level | Description | Status |
|---|---|---|
| 1 | Has tests | Done |
| 2 | Has CI with linting, typing, and multi-version testing | Done |
| 3 | Has security-specific test suites and dependency scanning | Done |
| 4 | Has independent security audit | Not yet |
| 5 | Has bug bounty program and formal CVE process | Not yet |

An independent security audit is planned before the 1.0 release.
