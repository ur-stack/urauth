# Best Practices

Recommendations for building secure, maintainable, and scalable applications with urauth. Each section includes real-world examples from common application types: SaaS platforms, enterprise systems, and marketplaces.

| Guide | What it covers |
|-------|---------------|
| [Security](security.md) | Secret keys, token TTL, CSRF, rate limiting, boundary validation |
| [Architecture](architecture.md) | Single auth instance, permission constants, role registries, guards, auth methods |
| [Multi-Tenancy](multi-tenancy.md) | Choosing a tenant model, embedding tenant in tokens, default roles, scoped permissions |
| [Access Control](access-control.md) | Least privilege, scoped permissions, composable requirements, DB-backed roles |
| [Testing](testing.md) | Test tokens, AuthOverride, tenant isolation, permission boundary tests |
| [Real-World Examples](examples.md) | Complete implementations for SaaS, enterprise, and marketplace apps |
| [Production Checklist](checklist.md) | 12-point launch readiness checklist |
