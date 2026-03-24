import { describe, test, expect } from "bun:test";
import {
  TokenService,
  RefreshService,
  RevocationService,
  MemoryTokenStore,
  TokenRevokedError,
  type AuthConfig,
} from "../src/index";

const config: AuthConfig = {
  secretKey: "test-secret-key-for-unit-tests-only",
  algorithm: "HS256",
  accessTokenTtl: 900,
  refreshTokenTtl: 604_800,
};

describe("RefreshService", () => {
  test("rotate issues new token pair", async () => {
    const store = new MemoryTokenStore();
    const tokenService = new TokenService(config);
    const refreshService = new RefreshService(tokenService, store, config);

    // Create initial pair
    const pair = await tokenService.createTokenPair("user-1", {
      familyId: "family-1",
    });

    // Track the refresh token
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      "family-1",
    );

    // Rotate
    const newPair = await refreshService.rotate(pair.refreshToken);
    expect(newPair.accessToken).toBeDefined();
    expect(newPair.refreshToken).toBeDefined();
    expect(newPair.tokenType).toBe("bearer");

    // Old token should be revoked
    expect(await store.isRevoked(refreshClaims.jti as string)).toBe(true);

    // New tokens should be valid
    const newAccess = await tokenService.validateAccessToken(newPair.accessToken);
    expect(newAccess.sub).toBe("user-1");
  });

  test("reuse detection revokes family", async () => {
    const store = new MemoryTokenStore();
    const tokenService = new TokenService(config);
    const refreshService = new RefreshService(tokenService, store, config);

    // Create and track a refresh token
    const pair = await tokenService.createTokenPair("user-1", {
      familyId: "family-1",
    });
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      "family-1",
    );

    // First rotation succeeds
    await refreshService.rotate(pair.refreshToken);

    // Second rotation with same token (reuse) should throw and revoke family
    try {
      await refreshService.rotate(pair.refreshToken);
      expect(true).toBe(false); // should not reach
    } catch (err) {
      expect(err).toBeInstanceOf(TokenRevokedError);
    }
  });
});

describe("RevocationService", () => {
  test("revoke and check", async () => {
    const store = new MemoryTokenStore();
    const service = new RevocationService(store);

    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    expect(await service.isRevoked("jti-1")).toBe(false);

    await service.revoke("jti-1", Date.now() / 1000 + 3600);
    expect(await service.isRevoked("jti-1")).toBe(true);
  });

  test("revokeAllForUser", async () => {
    const store = new MemoryTokenStore();
    const service = new RevocationService(store);

    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.addToken("jti-2", "user-1", "refresh", Date.now() / 1000 + 3600);

    await service.revokeAllForUser("user-1");
    expect(await service.isRevoked("jti-1")).toBe(true);
    expect(await service.isRevoked("jti-2")).toBe(true);
  });
});
