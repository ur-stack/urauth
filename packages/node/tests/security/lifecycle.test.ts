import { describe, test, expect } from "bun:test";
import { TokenLifecycle } from "../../src/lifecycle";
import { MemoryTokenStore } from "../../src/stores/memory";
import type { AuthConfig } from "../../src/config";
import { TokenRevokedError } from "@urauth/ts";

const SECRET = "test-secret-key-32-chars-long-xx";
const config: AuthConfig = { secretKey: SECRET, environment: "testing" };

function createLifecycle() {
  const store = new MemoryTokenStore();
  const lifecycle = new TokenLifecycle(config, store);
  return { store, lifecycle };
}

describe("TokenLifecycle — Replay Attack Scenarios", () => {
  test("validate() catches revoked token", async () => {
    const { lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    await lifecycle.revoke(issued.accessToken);

    await expect(lifecycle.validate(issued.accessToken)).rejects.toThrow(
      TokenRevokedError,
    );
  });

  test("validate() passes for non-revoked token", async () => {
    const { lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    const payload = await lifecycle.validate(issued.accessToken);
    expect(payload.sub).toBe("user-1");
    expect(payload.type).toBe("access");
  });

  test("revokeAll() prevents all user tokens from validating", async () => {
    const { lifecycle } = createLifecycle();
    const issued1 = await lifecycle.issue({ userId: "user-1" });
    const issued2 = await lifecycle.issue({ userId: "user-1" });

    await lifecycle.revokeAll("user-1");

    await expect(lifecycle.validate(issued1.accessToken)).rejects.toThrow(
      TokenRevokedError,
    );
    await expect(lifecycle.validate(issued2.accessToken)).rejects.toThrow(
      TokenRevokedError,
    );
  });

  test("refresh() works and new token validates", async () => {
    const { lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    const newPair = await lifecycle.refresh(issued.refreshToken);
    expect(newPair.accessToken).toBeTruthy();
    expect(newPair.refreshToken).toBeTruthy();

    // New access token should validate
    const payload = await lifecycle.validate(newPair.accessToken);
    expect(payload.sub).toBe("user-1");
  });

  test("old token after refresh rotation is revoked", async () => {
    const { lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    // Rotate
    await lifecycle.refresh(issued.refreshToken);

    // Old refresh token should be revoked — attempting to use it again triggers reuse detection
    await expect(lifecycle.refresh(issued.refreshToken)).rejects.toThrow(
      TokenRevokedError,
    );
  });

  test("multiple rapid rotations through lifecycle all succeed", async () => {
    const { lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    let currentRefreshToken = issued.refreshToken;
    for (let i = 0; i < 5; i++) {
      const newPair = await lifecycle.refresh(currentRefreshToken);
      expect(newPair.accessToken).toBeTruthy();
      expect(newPair.refreshToken).toBeTruthy();

      // Each new access token should validate
      const payload = await lifecycle.validate(newPair.accessToken);
      expect(payload.sub).toBe("user-1");

      currentRefreshToken = newPair.refreshToken;
    }
  });

  test("issue creates tokens tracked in store (not revoked initially)", async () => {
    const { store, lifecycle } = createLifecycle();
    const issued = await lifecycle.issue({ userId: "user-1" });

    // The access token's jti should be tracked and NOT revoked
    const payload = issued.payload;
    const isRevoked = await store.isRevoked(payload.jti);
    expect(isRevoked).toBe(false);
  });
});
