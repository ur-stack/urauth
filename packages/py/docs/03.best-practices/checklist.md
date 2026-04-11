# Production Checklist

Use this checklist when launching a urauth-based application:

- [ ] **Secret key** is set via environment variable (not default)
- [ ] **Access token TTL** is 15 minutes or less
- [ ] **Refresh token rotation** is enabled (`rotate_refresh_tokens=True`)
- [ ] **CSRF protection** is enabled if using cookie transport
- [ ] **Rate limiting** is applied to login and refresh endpoints
- [ ] **Permissions** are defined as constants (`PermissionEnum` or module-level)
- [ ] **Role registry** uses inheritance to avoid permission duplication
- [ ] **Guards** are used on every protected endpoint (no manual `if` checks)
- [ ] **Tenant isolation** is tested with cross-tenant access tests
- [ ] **Permission boundaries** are tested (both allow and deny paths)
- [ ] **Token store** uses Redis or a database in production (not `MemoryTokenStore`)
- [ ] **Optional auth** endpoints use `@auth.optional` (not a separate unprotected route)
