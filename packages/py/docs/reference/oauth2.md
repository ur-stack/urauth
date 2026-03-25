# OAuth2

OAuth2/OIDC social login support. OAuth2 provider models are documented under [Pipeline](pipeline.md#oauth-providers). The pipeline auto-generates OAuth routes when `OAuthLogin` is configured with one or more providers.

## TenantResolver

Resolves the current tenant from the request for multi-tenant applications.


> **`urauth.fastapi.authz.multi_tenant.TenantResolver`** — See source code for full API.

