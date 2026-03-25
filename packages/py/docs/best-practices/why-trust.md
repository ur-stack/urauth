# Why Trust urauth?

This page contains only verifiable claims backed by code references. No marketing language.

## Security by Default

urauth ships with secure defaults that require deliberate opt-out to weaken:

| Default | Code Reference | Effect |
|---|---|---|
| `httponly=True`, `secure=True`, `samesite="lax"` | `src/urauth/config.py` | Cookies are not accessible to JS and only sent over HTTPS |
| Algorithm pinning to `HS256` | `src/urauth/tokens/jwt.py` | Prevents algorithm confusion attacks (e.g., `none`, RS/HS substitution) |
| Reserved claim protection | `src/urauth/tokens/jwt.py` | Users cannot overwrite `sub`, `exp`, `iat`, `jti`, `iss`, `aud` via `extra_claims` |
| Fail-closed token store | `src/urauth/tokens/lifecycle.py` | If the store is unreachable, tokens are rejected (not silently accepted) |
| Refresh token rotation | `src/urauth/tokens/lifecycle.py` | Each refresh issues a new token and invalidates the old one |


> **`info`** — See source code for full API.

You can verify every claim above by reading the referenced source files directly.

:::

## What We Test

- **46 test files** covering unit, integration, and security scenarios.
- **85% coverage threshold** enforced in CI -- builds fail below this.
### Dedicated security regression suites:
    - `tests/unit/test_vulnerability_regression.py` -- known vulnerability patterns that must never reappear.
    - `tests/unit/test_tokens_security.py` -- token forgery, tampering, and replay scenarios.
    - `tests/unit/test_refresh_security.py` -- refresh rotation, reuse detection, and store failure behavior.

```text
tests/
  unit/
    test_vulnerability_regression.py
    test_tokens_security.py
    test_refresh_security.py
    ... (43 more files)
  integration/
    ...
```

## CI/CD Guarantees

Every pull request must pass all of the following before merge:

| Check | Tool | What It Catches |
|---|---|---|
| Linting | `ruff` | Style violations, unused imports, common bugs |
| Type checking | `basedpyright` (strict mode) | Type errors, missing annotations, unsafe casts |
| Tests | `pytest` on Python 3.10, 3.11, 3.12, 3.13 | Regressions across supported Python versions |
| Dependency scanning | `pip-audit` | Known CVEs in dependencies |
| Static analysis | `bandit` | Common security anti-patterns in Python code |


> **`warning`** — See source code for full API.

All checks run on every PR. There is no mechanism to skip them.

:::

## Minimal Dependencies

urauth has exactly **4 core runtime dependencies**:

| Dependency | Purpose | PyPI Downloads | Last CVE |
|---|---|---|---|
| `pydantic` | Config and data validation | 300M+/month | Actively maintained by Samuel Colvin / Pydantic Inc. |
| `pydantic-settings` | Environment-based configuration | Part of Pydantic ecosystem | Same maintainers as Pydantic |
| `PyJWT` | JWT encode/decode | 100M+/month | Well-audited, used by major cloud SDKs |
| `bcrypt` | Password hashing | 50M+/month | Thin wrapper around the OpenBSD bcrypt C implementation |

No transitive dependencies beyond what these four bring in. You can verify with:

```bash
pip install urauth && pip show urauth | grep Requires
```

## What We Don't Do

- **No custom cryptography.** All crypto operations delegate to PyJWT (HMAC-SHA256) and bcrypt.
- **No novel constructions.** Token format is standard JWT (RFC 7519). Password hashing is standard bcrypt.
- **No insecure algorithms.** The `none` algorithm is never accepted. Only `HS256` is enabled by default. Algorithm switching requires explicit configuration.
- **No rolling our own session management.** Token storage is pluggable and delegates to battle-tested backends (Redis, SQL databases).

## Honest Maturity Assessment

urauth is **pre-1.0 software**. Here is where it stands on a 5-level maturity scale:

| Level | Description | Status |
|---|---|---|
| 1 | Has tests | Done |
| 2 | Has CI with linting, typing, and multi-version testing | Done |
| 3 | Has security-specific test suites and dependency scanning | Done |
| 4 | Has independent security audit | Not yet |
| 5 | Has bug bounty program and CVE process | Not yet |

**Current level: 2-3.**

What we are actively working toward:

- [ ] Independent security audit before 1.0 release
- [ ] Formal CVE disclosure process
- [ ] SECURITY.md with responsible disclosure instructions


> **`info`** — See source code for full API.

If you are evaluating urauth for production use, read the [Safe Usage Guide](safe-usage.md) for hardening recommendations.

:::