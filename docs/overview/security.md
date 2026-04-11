# Security

## Open Source Security Model

urauth is fully open source, and that is a deliberate security decision.

Security by obscurity — hiding implementation details to slow attackers down — is not a security model. It is a temporary inconvenience that fails the moment source code leaks, someone decompiles the binary, or an attacker spends enough time probing the system. urauth rejects that approach entirely.

Instead, urauth is designed around **Kerckhoffs's principle**: the security of the system must not depend on secrecy of the design. An attacker who reads every line of this library's source code, every document in this repository, and every comment in every commit should still be unable to forge a token, escalate privileges, or cross a tenant boundary — because the protection comes from secrets the attacker does not have (your `secret_key`), not from implementation details they might eventually discover.

This means:

- **The algorithms are public.** Token signing uses standard HMAC-SHA256 (HS256) via PyJWT. There is no proprietary encoding, custom obfuscation, or undocumented twist.
- **The threat model is documented.** The attack vectors we defend against are listed explicitly. You do not have to guess what is in scope.
- **The defaults are visible.** Every secure-by-default choice — `httpOnly` cookies, algorithm pinning, reserved claim protection — is documented and auditable.
- **The source is reviewable.** Security researchers, auditors, and users can read exactly what the library does. Audits do not require a private disclosure process to obtain the source.

Openness also creates accountability. A library that hides its internals can make false claims about its security properties. One that publishes everything can be checked. Bugs found by external reviewers are bugs fixed before they reach production.

The corollary: **if you find a behavior in urauth that is only safe because it is undocumented or surprising, that is a bug.** Security in this library should be legible.

## Secure Defaults

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

## No Custom Cryptography

All cryptographic operations are delegated to audited, widely-deployed libraries:

- **JWT signing and verification** — [PyJWT](https://pyjwt.readthedocs.io/) (100M+ downloads/month), which uses Python's `hmac.compare_digest` for constant-time HMAC verification.
- **Password hashing** — [bcrypt](https://pypi.org/project/bcrypt/) (50M+ downloads/month), a thin wrapper around the OpenBSD bcrypt C implementation.

urauth does not implement any custom cryptographic primitives. Token format is standard JWT (RFC 7519). There are no novel constructions.

## Authentication Security Recommendations

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

## Vulnerability Response

### Reporting

**Do not report security vulnerabilities through public GitHub issues.** Public disclosure before a fix is available puts every application using urauth at risk.

Use [GitHub Security Advisories](https://github.com/ur-stack/urauth/security/advisories/new) to report privately. Include:

- Description of the vulnerability
- Steps to reproduce or a proof of concept
- Impact assessment (what can an attacker achieve?)
- Affected versions
- Suggested fix, if you have one

### Response Timeline

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

### What We Monitor

- **GitHub Dependabot / security alerts** — all dependency vulnerabilities are tracked automatically. We update affected dependencies promptly on notification.
- **`pip-audit` in CI** — every build scans for known CVEs in the dependency tree. A build that introduces a CVE-bearing dependency fails before merge.
- **Manual triage** — new CVEs in `PyJWT`, `bcrypt`, `pydantic`, and `pydantic-settings` are reviewed as they are published.

### Scope

| In scope | Out of scope |
|---|---|
| Authentication bypass | Denial of service (unless caused by a small input) |
| Token forgery or manipulation | Issues requiring physical server access |
| Secret key leakage | Social engineering |
| Privilege escalation | Issues in dependencies (report upstream; we update promptly) |
| Injection vulnerabilities | Misconfiguration by the user (but suggestions to make it harder are welcome) |
| Cryptographic weaknesses | |
| Cross-tenant data access | |

### Disclosure Process

We follow coordinated disclosure:

1. Reporter submits vulnerability privately via GitHub Security Advisories.
2. We acknowledge within 48 hours and confirm scope.
3. We develop and test a fix, keeping the reporter informed.
4. We release the fix with a patch version bump and publish a GitHub Security Advisory.
5. Reporter is credited in the advisory and CHANGELOG unless they request anonymity.

We will not take legal action against researchers who act in good faith.

### Maturity Level

urauth is pre-1.0 software. Here is an honest assessment of where it stands:

| Level | Description | Status |
|---|---|---|
| 1 | Has tests | Done |
| 2 | Has CI with linting, typing, and multi-version testing | Done |
| 3 | Has security-specific test suites and dependency scanning | Done |
| 4 | Has independent security audit | Not yet |
| 5 | Has bug bounty program and formal CVE process | Not yet |

An independent security audit is planned before the 1.0 release.
