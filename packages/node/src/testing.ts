/**
 * Test helpers — mock auth and context factories for unit tests.
 */

import { AuthContext, Permission, Role, type AuthContextOptions } from "@urauth/ts";
import type { TokenPayload } from "@urauth/ts";

/** Create a mock AuthContext with sensible defaults. */
export function mockContext(overrides: Partial<AuthContextOptions> = {}): AuthContext {
  return new AuthContext({
    user: overrides.user ?? { id: "test-user", name: "Test User" },
    roles: overrides.roles ?? [],
    permissions: overrides.permissions ?? [],
    relations: overrides.relations ?? [],
    authenticated: overrides.authenticated ?? true,
    token: overrides.token,
    request: overrides.request,
    tenant: overrides.tenant,
    scopes: overrides.scopes,
  });
}

/** Create a mock admin context with all permissions. */
export function mockAdminContext(overrides: Partial<AuthContextOptions> = {}): AuthContext {
  return mockContext({
    user: { id: "admin", name: "Admin" },
    roles: [new Role("admin")],
    permissions: [new Permission("*")],
    ...overrides,
  });
}

/** Create an anonymous (unauthenticated) context. */
export function mockAnonymousContext(): AuthContext {
  return AuthContext.anonymous();
}

/** Create a mock TokenPayload. */
export function mockPayload(overrides: Partial<TokenPayload> = {}): TokenPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: "test-user",
    jti: "test-jti-" + Math.random().toString(36).slice(2),
    iat: now,
    exp: now + 900,
    type: "access",
    ...overrides,
  };
}
