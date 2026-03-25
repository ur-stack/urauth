# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use [GitHub Security Advisories](https://github.com/grandmagus/urauth/security/advisories/new) to report vulnerabilities privately.

Include as much of the following as possible:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Impact assessment (what can an attacker achieve?)
- Affected versions
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours of report
- **Initial assessment:** Within 5 business days
- **Fix for critical issues:** Within 7 days of confirmed vulnerability
- **Fix for non-critical issues:** Within 30 days

## What Counts as a Security Issue

**In scope:**
- Authentication bypass
- Token forgery or manipulation
- Secret key leakage
- Privilege escalation
- Injection vulnerabilities
- Cryptographic weaknesses
- Cross-tenant data access

**Out of scope:**
- Denial of service (unless caused by a small input)
- Issues requiring physical access to the server
- Social engineering
- Issues in dependencies (report upstream; we will update promptly)
- Misconfiguration by the user (but we welcome suggestions to make misconfiguration harder)

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We acknowledge and assess
3. We develop and test a fix
4. We release the fix and publish an advisory
5. Reporter is credited (unless they prefer anonymity)

We will not take legal action against researchers who act in good faith.

## Credit

We credit all reporters in our security advisories and CHANGELOG unless they request anonymity.

## Scope and Limitations

urauth protects against:
- Token forgery (JWT signature verification with algorithm pinning)
- Token replay (refresh token family-based reuse detection)
- Token type confusion (access vs refresh discrimination)
- Claim injection (reserved claim protection)
- Weak password storage (bcrypt with configurable rounds)

urauth does **not** protect against:
- Compromised host or stolen signing key
- Missing TLS (assumes HTTPS is configured)
- Application-level vulnerabilities (SQL injection, XSS)
- Rate limiting (opt-in, not enforced by default)
- DDoS attacks

See the [threat model](packages/py/docs/best-practices/threat-model.md) for full details.
