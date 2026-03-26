import { describe, test, expect } from "bun:test";
import { TokenService } from "../../src/tokens/jwt";
import { RefreshService } from "../../src/tokens/refresh";
import { MemoryTokenStore } from "../../src/stores/memory";
import { TokenRevokedError } from "@urauth/ts";
import type { AuthConfig } from "../../src/config";

const SECRET = "test-secret-key-32-chars-long-xx";
const config: AuthConfig = { secretKey: SECRET, environment: "testing" };

function createServices() {
  const tokenService = new TokenService(config);
  const store = new MemoryTokenStore({ strict: false });
  const refreshService = new RefreshService(tokenService, store, config);
  return { tokenService, store, refreshService };
}

describe("Refresh Token Rotation Security", () => {
  test("normal rotation works and returns new pair", async () => {
    const { tokenService, store, refreshService } = createServices();

    // Create initial pair and track in store
    const pair = await tokenService.createTokenPair("user-1");
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    const familyId = crypto.randomUUID().replace(/-/g, "");
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      familyId,
    );

    // Rotate
    const newPair = await refreshService.rotate(pair.refreshToken);
    expect(newPair.accessToken).toBeDefined();
    expect(newPair.refreshToken).toBeDefined();
    expect(newPair.accessToken).not.toBe(pair.accessToken);
    expect(newPair.refreshToken).not.toBe(pair.refreshToken);
  });

  test("replaying old refresh token after rotation triggers reuse detection", async () => {
    const { tokenService, store, refreshService } = createServices();

    const pair = await tokenService.createTokenPair("user-1");
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    const familyId = crypto.randomUUID().replace(/-/g, "");
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      familyId,
    );

    // First rotation succeeds
    await refreshService.rotate(pair.refreshToken);

    // Replay the old token — should detect reuse
    await expect(refreshService.rotate(pair.refreshToken)).rejects.toThrow(
      TokenRevokedError,
    );
  });

  test("reuse detection revokes entire family", async () => {
    const { tokenService, store, refreshService } = createServices();

    const pair = await tokenService.createTokenPair("user-1");
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    const familyId = crypto.randomUUID().replace(/-/g, "");
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      familyId,
    );

    // Rotate to get new tokens in the same family
    const newPair = await refreshService.rotate(pair.refreshToken);

    // Replay old token — triggers family revocation
    try {
      await refreshService.rotate(pair.refreshToken);
    } catch {
      // Expected
    }

    // The new tokens should also be revoked (same family)
    const newRefreshClaims = await tokenService.decodeToken(
      newPair.refreshToken,
    );
    const isRevoked = await store.isRevoked(newRefreshClaims.jti as string);
    expect(isRevoked).toBe(true);
  });

  test("family isolation: revoking family A does not affect family B", async () => {
    const { tokenService, store, refreshService } = createServices();

    // Family A
    const pairA = await tokenService.createTokenPair("user-1");
    const claimsA = await tokenService.decodeToken(pairA.refreshToken);
    const familyA = "family-a";
    await store.addToken(
      claimsA.jti as string,
      "user-1",
      "refresh",
      claimsA.exp as number,
      familyA,
    );

    // Family B
    const pairB = await tokenService.createTokenPair("user-1");
    const claimsB = await tokenService.decodeToken(pairB.refreshToken);
    const familyB = "family-b";
    await store.addToken(
      claimsB.jti as string,
      "user-1",
      "refresh",
      claimsB.exp as number,
      familyB,
    );

    // Rotate family A, then replay to trigger revocation
    await refreshService.rotate(pairA.refreshToken);
    try {
      await refreshService.rotate(pairA.refreshToken);
    } catch {
      // Expected reuse detection
    }

    // Family B tokens should NOT be revoked
    const isBRevoked = await store.isRevoked(claimsB.jti as string);
    expect(isBRevoked).toBe(false);
  });

  test("new tokens after rotation are tracked in store", async () => {
    const { tokenService, store, refreshService } = createServices();

    const pair = await tokenService.createTokenPair("user-1");
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    const familyId = crypto.randomUUID().replace(/-/g, "");
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      familyId,
    );

    const newPair = await refreshService.rotate(pair.refreshToken);

    // New tokens should be tracked (not revoked)
    const newAccessClaims = await tokenService.decodeToken(newPair.accessToken);
    const newRefreshClaims = await tokenService.decodeToken(
      newPair.refreshToken,
    );

    expect(await store.isRevoked(newAccessClaims.jti as string)).toBe(false);
    expect(await store.isRevoked(newRefreshClaims.jti as string)).toBe(false);
  });

  test("new tokens after rotation maintain same family", async () => {
    const { tokenService, store, refreshService } = createServices();

    const pair = await tokenService.createTokenPair("user-1", {
      familyId: "my-family",
    });
    const refreshClaims = await tokenService.decodeToken(pair.refreshToken);
    await store.addToken(
      refreshClaims.jti as string,
      "user-1",
      "refresh",
      refreshClaims.exp as number,
      "my-family",
    );

    const newPair = await refreshService.rotate(pair.refreshToken);
    const newRefreshClaims = await tokenService.decodeToken(
      newPair.refreshToken,
    );
    const newFamilyId = await store.getFamilyId(
      newRefreshClaims.jti as string,
    );
    expect(newFamilyId).toBe("my-family");
  });

  test("missing jti/sub in token claims throws error", async () => {
    // We cannot easily create a token with missing jti/sub via TokenService
    // since it always sets them. Instead we test that RefreshService correctly
    // validates claims. We'll use a mock approach: create a valid token and
    // verify the service works, then test the error path.
    const { tokenService, store } = createServices();

    // Create a custom token service that uses a token without claims validation
    // by using the jose library directly to create a malformed token
    const jose = await import("jose");
    const secret = new TextEncoder().encode(SECRET);

    // Token missing sub claim
    const malformedToken = await new jose.SignJWT({ type: "refresh", jti: "test-jti" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(secret);

    const refreshService = new RefreshService(tokenService, store, config);
    await expect(refreshService.rotate(malformedToken)).rejects.toThrow();
  });
});
