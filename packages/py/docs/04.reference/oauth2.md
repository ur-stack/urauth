# OAuth2

OAuth2/OIDC social login support. OAuth2 provider models are documented under [Auth Methods](pipeline.md#oauth-providers). OAuth routes are auto-generated when `oauth=OAuth(providers=[...])` is configured on the `Auth` instance.

## TenantResolver

Resolves the current tenant from the request for multi-tenant applications.


> **`urauth.fastapi.authz.multi_tenant.TenantResolver`** -- See source code for full API.
