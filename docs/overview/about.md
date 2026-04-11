# About

## What urauth Does

Authentication and authorization are solved problems with well-understood patterns — but most frameworks either leave them entirely to the developer or provide solutions that are hard to extend, hard to test, or insecure by default. urauth occupies the space in between: it handles the common 90% with safe defaults, and exposes every extension point as a clean protocol so you can replace any part of it.

### Core Capabilities

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

### What urauth Is Not

urauth does not protect against compromised infrastructure (stolen signing key, misconfigured TLS, SQL injection in your application). It assumes HTTPS is in place, handles the cryptographic identity layer, and stops there. See the [Threat Model](/packages/py/best-practices/threat-model) for a precise statement of scope.

---

## Code Maintenance

### Continuous Integration

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

### Minimal Dependencies

urauth has exactly four core runtime dependencies:

| Dependency | Purpose |
|---|---|
| `pydantic` | Config and data validation |
| `pydantic-settings` | Environment-based configuration |
| `PyJWT` | JWT encode/decode |
| `bcrypt` | Password hashing |

Smaller dependency surface means fewer CVEs to track and fewer transitive supply-chain risks. Optional extras (`fastapi`, `oauth`, `redis`, `sqlalchemy`) are not installed unless the application explicitly requests them.

### Versioning and Changelog

urauth follows [semantic versioning](https://semver.org/). Breaking changes only in major versions. Every release includes a changelog entry generated from commit history. Supported version ranges are listed in `SECURITY.md`.

---

## Testing

### Test Structure

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

### Security-Specific Test Suites

Three test files are dedicated exclusively to security regression testing:

- **`tests/unit/test_vulnerability_regression.py`** — a running catalogue of known vulnerability patterns (algorithm confusion, claim injection, token replay, etc.) that must never reappear. Each test is written when a class of vulnerability is identified, even if it was never exploited.
- **`tests/unit/test_tokens_security.py`** — exhaustive tests for token forgery, header tampering, payload manipulation, and signature stripping.
- **`tests/unit/test_refresh_security.py`** — tests for refresh token rotation correctness, reuse detection triggering family-wide revocation, and store-failure fail-closed behavior.

### Fuzz and Property-Based Testing

urauth uses [Hypothesis](https://hypothesis.readthedocs.io/) for property-based testing. Key invariants tested:

- Any mutation of a signed token must fail verification.
- Any token whose `exp` claim is in the past must be rejected.
- Any token with an algorithm not in the allowed list must be rejected.
- Refresh token reuse must always trigger family revocation, regardless of timing.

### Testing Your Application

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
