# Threat Model

This document describes the security threats that urauth is designed to address, the
mitigations it provides, and the residual risks that remain the responsibility of the
application developer or deployment environment.

The format follows **Asset / Threat / Mitigation / Residual Risk** for each area.

## Summary

| Area | Severity | urauth Mitigation | Residual Risk |
|---|---|---|---|
| Token creation & validation | Critical | Algorithm pinning, reserved claim protection, type validation | Signing key compromise, JWT parsing side-channels |
| Refresh token flow | High | Family-based reuse detection, rotation, revocation | Race condition window during rotation |
| Password hashing | High | bcrypt with 12 rounds and salt | GPU-accelerated brute force, 72-byte truncation |
| Cookie transport & sessions | High | httponly, secure, samesite defaults | Misconfigured cookie flags, missing CSRF opt-in |
| Secret key management | Critical | Key validation, weak key blocklist, min-length enforcement | No built-in key rotation |
| Multi-tenant isolation | High | JWT claim precedence, hierarchy checks, TenantGuard | Unguarded routes, DNS-based subdomain trust |
| Authorization (RBAC/Relations) | Medium | Circular reference detection, composable type-safe requirements | Global wildcard grants everything |

## 1. Token Creation & Validation

### Assets

- **JWT signing key** (`Auth(secret_key=...)`) -- the single secret protecting all tokens.
- **Access tokens** -- short-lived JWTs authorizing API requests.
- **Refresh tokens** -- longer-lived JWTs used to obtain new access tokens.

### Threats

| Threat | Description |
|---|---|
| Algorithm confusion (`alg=none`) | Attacker submits a token with `alg: "none"` or switches from RSA to HMAC to bypass signature verification. |
| Claim injection | Attacker passes extra claims that overwrite `sub`, `exp`, `jti`, or other reserved fields to impersonate users or extend token lifetime. |
| Type confusion | A refresh token is presented where an access token is expected (or vice versa) to bypass authorization checks. |
| Token forgery | Attacker crafts a token with a guessed or leaked signing key. |

### Mitigations

- **Algorithm pinning.** `TokenService.decode_token()` passes `algorithms=[self._config.algorithm]` to PyJWT, which rejects any token whose `alg` header does not match the single configured algorithm. The `alg=none` attack is blocked because `"none"` is never in the allowed list.

- **Reserved claim protection.** `create_access_token()` filters `extra_claims` against a hardcoded set:

    ```python
    reserved = {"sub", "jti", "iat", "exp", "iss", "aud", "type"}
    claims.update({k: v for k, v in extra_claims.items() if k not in reserved})
    ```

    Application code cannot accidentally or intentionally overwrite identity or expiry claims.

- **Token type validation.** `validate_access_token()` checks `claims.get("type") != "access"` and raises `InvalidTokenError`. `validate_refresh_token()` does the same for `"refresh"`. A refresh token cannot be used as an access token.

- **PyJWT handles cryptography.** urauth delegates all signing, verification, and expiry checks to PyJWT, which uses well-audited implementations.

### Residual Risks

::: warning Signing key compromise
If the signing key is leaked, all tokens can be forged. urauth validates the key
at startup but cannot protect against runtime exfiltration. See
[Secret Key Management](#5-secret-key-management).

:::
::: info Timing side-channels in JWT parsing
PyJWT uses Python's `hmac.compare_digest` for HMAC verification, which is
constant-time. However, other steps in token parsing (base64 decoding, JSON
deserialization) may leak timing information. This is a theoretical risk shared
by all JWT libraries.

:::

## 2. Refresh Token Flow

### Assets

- **Refresh tokens** -- long-lived credentials (default: 7 days).
- **Token families** -- groups of tokens sharing a `family_id`, representing a single session lineage.

### Threats

| Threat | Description |
|---|---|
| Token replay | Attacker captures a refresh token and replays it after the legitimate user has already used it. |
| Family escape | Attacker obtains a refresh token and uses it before the legitimate user, creating a forked family that survives reuse detection. |
| Reuse detection bypass | Attacker finds a way to use a revoked refresh token without triggering family-wide revocation. |

### Mitigations

- **Family-based reuse detection.** `TokenLifecycle.refresh()` checks `store.is_revoked(jti)` before processing. If the token was already consumed, the entire family is revoked:

    ```python
    if await self.store.is_revoked(jti):
        family_id = await self.store.get_family_id(jti)
        if family_id:
            await self.store.revoke_family(family_id)
        else:
            await self.store.revoke_all_for_user(user_id)
        raise TokenRevokedError("Refresh token reuse detected — all tokens revoked")
    ```

- **Rotation on refresh.** Every successful refresh immediately revokes the old refresh token and issues a new pair within the same family. The window in which the old token is valid is minimal.

- **Fallback to user-wide revocation.** If `family_id` lookup fails (e.g., store inconsistency), `revoke_all_for_user()` is called as a safety net.

### Residual Risks

::: warning Race condition during rotation
If two requests arrive simultaneously with the same refresh token, both may pass
the `is_revoked` check before either revokes the old token. This is an inherent
limitation of non-transactional token stores. Use a token store with atomic
operations (e.g., Redis with `SETNX`) to minimize this window.

:::

## 3. Password Hashing

### Assets

- **User passwords** -- plaintext credentials during authentication.
- **Password hashes** -- stored bcrypt digests.

### Threats

| Threat | Description |
|---|---|
| Brute force | Attacker obtains hashed passwords and attempts offline cracking. |
| Timing attacks | Attacker measures response time to determine whether a username exists or a password prefix matches. |
| Rainbow tables | Attacker uses precomputed hash tables to reverse common passwords. |
| bcrypt 72-byte truncation | bcrypt silently truncates passwords longer than 72 bytes, meaning two passwords sharing the same first 72 bytes produce identical hashes. |

### Mitigations

- **bcrypt with 12 rounds.** The default `password_hash_scheme` is `"bcrypt"`, which uses a cost factor of 12 (approximately 250ms per hash on modern hardware). This makes brute-force attacks computationally expensive.

- **Automatic salting.** bcrypt generates a unique random salt for each hash, making rainbow tables ineffective.

- **Constant-time comparison.** The bcrypt library's `checkpw()` function performs constant-time comparison internally, preventing timing-based password guessing.

- **72-byte limit documented.** The bcrypt 72-byte truncation is a known limitation. Applications handling passwords that may exceed this length should pre-hash with SHA-256 before passing to bcrypt.

### Residual Risks

::: info GPU-accelerated brute force
bcrypt is intentionally resistant to GPU acceleration due to its memory-hard
design, but it is not immune. Very high-value targets with weak passwords may
still be crackable with sufficient resources. Enforce minimum password complexity
at the application level.

:::

## 4. Cookie Transport & Sessions

### Assets

- **Session cookies** (`session_id`) -- identify server-side sessions.
- **Access token cookies** (`access_token`) -- carry JWTs in cookie transport mode.

### Threats

| Threat | Description |
|---|---|
| XSS token theft | Malicious JavaScript reads token cookies and exfiltrates them. |
| CSRF | Attacker tricks an authenticated user's browser into making state-changing requests. |
| Session fixation | Attacker sets a known session ID before the user authenticates. |

### Mitigations

- **Secure cookie defaults.** urauth sets all cookie flags defensively out of the box:

    | Flag | Default | Effect |
    |---|---|---|
    | `cookie_httponly` | `True` | Prevents JavaScript access to the cookie |
    | `cookie_secure` | `True` | Cookie only sent over HTTPS |
    | `cookie_samesite` | `"lax"` | Blocks cross-origin POST requests with cookies |
    | `session_cookie_httponly` | `True` | Same protection for session cookies |
    | `session_cookie_secure` | `True` | Same protection for session cookies |
    | `session_cookie_samesite` | `"lax"` | Same protection for session cookies |

- **CSRF middleware available.** CSRF can be enabled (via `AUTH_CSRF_ENABLED=true` environment variable) to enable double-submit cookie CSRF protection via `csrf_cookie_name` and `csrf_header_name`.

- **Session regeneration.** New session IDs are generated on login, preventing fixation attacks when the application follows the documented flow.

### Residual Risks

::: warning CSRF is opt-in
CSRF protection is disabled by default (`csrf_enabled=False`). Applications using
cookie transport for state-changing requests **must** enable it or implement their
own CSRF protection.

:::
::: info Misconfigured cookie flags
If an application overrides `cookie_httponly=False`, tokens become readable by
JavaScript. urauth provides safe defaults but cannot prevent intentional override.

:::

## 5. Secret Key Management

### Assets

- **`Auth(secret_key=...)`** -- the HMAC signing key (or PEM key for RSA/EC).

### Threats

| Threat | Description |
|---|---|
| Weak keys | Short or predictable keys that can be brute-forced. |
| Default keys in production | Forgetting to change the development default `"CHANGE-ME-IN-PRODUCTION"`. |
| Key in source control | Hardcoding the key in application code and committing it to a repository. |

### Mitigations

- **Default key raises `ValueError`.** If `secret_key` is still `"CHANGE-ME-IN-PRODUCTION"` and `allow_insecure_key` is `False` (the default), `Auth` raises immediately at startup:

    ```
    ValueError: urauth: Default secret key 'CHANGE-ME-IN-PRODUCTION' is not allowed.
    Set AUTH_SECRET_KEY environment variable or pass a secure key.
    ```

- **Minimum length enforcement.** For HMAC algorithms (HS256, HS384, HS512), the key must be at least 32 characters. Shorter keys raise `ValueError`.

- **Weak key blocklist.** Common weak secrets (`"secret"`, `"password"`, `"changeme"`, `"test"`, `"key"`, `"mysecret"`, `"jwt-secret"`, etc.) are rejected at startup.

- **Environment-based configuration.** urauth reads `AUTH_*` environment variables via pydantic-settings, encouraging `AUTH_SECRET_KEY` as an environment variable rather than a hardcoded value.

### Residual Risks

::: warning No built-in key rotation
urauth does not support multiple active signing keys or key rotation. Rotating
the key invalidates all existing tokens. Applications requiring zero-downtime
rotation must implement a dual-key verification layer externally.

:::
::: info Key in environment
While environment variables are better than source code, they may still appear
in process listings, container inspection, or CI logs. Use a secrets manager
(Vault, AWS Secrets Manager, etc.) for production deployments.

:::

## 6. Multi-Tenant Isolation

### Assets

- **Tenant data boundaries** -- ensuring users in one tenant cannot access another tenant's resources.
- **Tenant hierarchy** -- parent/child relationships between organizational units.

### Threats

| Threat | Description |
|---|---|
| Cross-tenant access | A user in tenant A accesses resources belonging to tenant B. |
| Privilege escalation via hierarchy | A user at a child tenant gains access to parent-level resources. |
| Header spoofing | Attacker sets the `X-Tenant-ID` header to impersonate a different tenant. |

### Mitigations

- **JWT claim precedence over headers.** When a tenant claim is present in the JWT, it takes precedence over the `X-Tenant-ID` header. An attacker cannot override their tenant by spoofing headers if the token was issued with a tenant claim.

- **TenantPath hierarchy checks.** `TenantPath` provides `contains()` and `is_descendant_of()` methods for structural validation. These prevent a child tenant from claiming parent-level access without explicit hierarchy traversal.

- **TenantGuard enforcement.** The `TenantGuard` dependency validates that the authenticated context includes the required tenant and that the user's tenant path is compatible with the requested resource.

### Residual Risks

::: warning Routes without TenantGuard run tenant-less
Any route that does not apply `TenantGuard` has no tenant isolation. There is no
global enforcement -- each route must opt in. Consider adding a middleware or
startup check that audits route coverage.

:::
::: info Subdomain extraction trusts DNS
If tenant identification relies on subdomain extraction (e.g., `acme.app.com`),
the application trusts that DNS resolution is correct. DNS spoofing or wildcard
certificate misuse could allow tenant impersonation at the network level.

:::

## 7. Authorization (RBAC / Relations)

### Assets

- **Permissions** -- fine-grained capabilities (e.g., `"task:read"`, `"billing:*"`).
- **Roles** -- named permission bundles with optional inheritance.
- **Resource access** -- authorization decisions on specific resources.

### Threats

| Threat | Description |
|---|---|
| Permission wildcard abuse | A role with `"*"` (global wildcard) grants access to every resource, including future ones. |
| Circular role hierarchy | Role A inherits from Role B, which inherits from Role A, causing infinite loops in permission expansion. |
| Permission injection | Attacker manipulates the roles or permissions list in the JWT to escalate privileges. |

### Mitigations

- **Circular reference detection.** `RoleExpandingChecker` tracks visited roles during expansion and stops if a cycle is detected, preventing infinite loops and stack overflows.

- **Composable requirements with type safety.** Authorization rules are built using `Requirement` objects composed with `&` (AND) and `|` (OR). These are Python objects, not strings -- they cannot be injected via request data.

- **Checker protocol.** All authorization checks flow through a `PermissionChecker` protocol operating on `AuthContext`. The checker receives roles and permissions from the validated token, not from user-supplied request data.

### Residual Risks

::: warning Global wildcard (`*`) grants everything
The `match_permission()` function treats `"*"` as a universal match. Any role
assigned the `"*"` permission effectively bypasses all permission checks.
Assign this only to the highest-trust administrative roles, and audit its usage.

:::
::: info Permission semantics are application-defined
urauth provides the matching engine but does not define what permissions mean.
A permission like `"user:delete"` only works if the application checks it at
the right enforcement point. Missing checks are invisible to urauth.

:::

## Non-Goals

The following threats are explicitly **outside the scope** of urauth. They must be
addressed by the application, infrastructure, or complementary libraries.

| Threat | Why it is out of scope |
|---|---|
| **Compromised host or stolen signing key** | If the server is compromised, all bets are off. Key protection is an infrastructure concern. |
| **Application-level SQL injection / XSS** | urauth does not interact with databases directly or render HTML. These are application responsibilities. |
| **Missing TLS configuration** | urauth sets `cookie_secure=True` by default but cannot enforce HTTPS at the network level. |
| **DDoS / rate limiting** | Rate limiting is available as an opt-in how-to guide but is not part of the core security model. |
| **User enumeration (timing-based)** | Login endpoints may leak whether a username exists via response timing. This must be mitigated at the application level (e.g., constant-time fake hash on unknown users). |
| **OAuth provider vulnerabilities** | urauth integrates with OAuth providers but cannot control their security posture. |

## Recommended Reading

- [Security Best Practices](security.md) -- practical hardening steps for production deployments.
- [Production Checklist](checklist.md) -- a step-by-step checklist before going live.
- [Configuration Reference](../reference/config.md) -- all `AuthConfig` fields and their security implications.
