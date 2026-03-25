# @urauth/node

Node.js backend SDK for urauth. Builds on top of `@urauth/ts` to add JWT creation/verification, token lifecycle management, refresh token rotation, and pluggable stores.

## Installation

```bash
pnpm add @urauth/node
```

## What This Package Adds

| Feature | Description |
|---------|-------------|
| `TokenService` | Create and verify JWTs using [jose](https://github.com/panva/jose) |
| `RefreshService` | Token rotation with family-based reuse detection |
| `RevocationService` | Token revocation via `TokenStore` |
| `MemoryTokenStore` | In-memory token store for dev/testing |
| `MemorySessionStore` | In-memory session store for dev/testing |

## Quick Start

```typescript
import { TokenService, RefreshService } from "@urauth/node";

const tokenService = new TokenService({
  secretKey: "your-secret-key",
  algorithm: "HS256",
  issuer: "my-app",
  accessTokenTtl: 900,     // 15 minutes
  refreshTokenTtl: 604800, // 7 days
});

// Create token pair
const pair = await tokenService.createTokenPair("user-123", {
  roles: ["editor"],
  tenantPath: { organization: "acme", team: "alpha" },
});

// Verify access token
const payload = await tokenService.validateAccessToken(pair.accessToken);
```

## Dependencies

- `@urauth/ts` — shared types and authorization primitives
- `jose` — JWT creation and verification

::: info
Documentation is being expanded. See the [@urauth/ts docs](/packages/ts/) for the shared authorization API.
:::
