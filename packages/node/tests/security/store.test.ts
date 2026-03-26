import { describe, test, expect } from "bun:test";
import {
  MemoryTokenStore,
  MemorySessionStore,
} from "../../src/stores/memory";

describe("MemoryTokenStore Security", () => {
  test("strict mode: unknown JTI treated as revoked (fail-closed)", async () => {
    const store = new MemoryTokenStore({ strict: true });
    expect(await store.isRevoked("unknown-jti")).toBe(true);
  });

  test("non-strict mode: unknown JTI treated as not revoked", async () => {
    const store = new MemoryTokenStore({ strict: false });
    expect(await store.isRevoked("unknown-jti")).toBe(false);
  });

  test("revoked token returns true for isRevoked", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.revoke("jti-1", Date.now() / 1000 + 3600);
    expect(await store.isRevoked("jti-1")).toBe(true);
  });

  test("known non-revoked token returns false", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    expect(await store.isRevoked("jti-1")).toBe(false);
  });

  test("revokeAllForUser revokes all user tokens", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.addToken("jti-2", "user-1", "refresh", Date.now() / 1000 + 3600);
    await store.addToken("jti-3", "user-1", "access", Date.now() / 1000 + 3600);

    await store.revokeAllForUser("user-1");

    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(true);
    expect(await store.isRevoked("jti-3")).toBe(true);
  });

  test("revokeAllForUser does not affect other users", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.addToken("jti-2", "user-2", "access", Date.now() / 1000 + 3600);

    await store.revokeAllForUser("user-1");

    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(false);
  });

  test("revokeFamily revokes all tokens in family", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600, "family-a");
    await store.addToken("jti-2", "user-1", "refresh", Date.now() / 1000 + 3600, "family-a");
    await store.addToken("jti-3", "user-1", "access", Date.now() / 1000 + 3600, "family-a");

    await store.revokeFamily("family-a");

    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(true);
    expect(await store.isRevoked("jti-3")).toBe(true);
  });

  test("revokeFamily does not affect other families", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600, "family-a");
    await store.addToken("jti-2", "user-1", "access", Date.now() / 1000 + 3600, "family-b");

    await store.revokeFamily("family-a");

    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(false);
  });

  test("getFamilyId returns correct family", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600, "family-x");
    expect(await store.getFamilyId("jti-1")).toBe("family-x");
  });
});

describe("MemorySessionStore Security", () => {
  test("expired session returns undefined", async () => {
    const store = new MemorySessionStore();
    // Create session with TTL of 0 (immediately expired)
    await store.create("sid-1", "user-1", { role: "admin" }, 0);

    // Wait a tiny bit to ensure expiration
    await new Promise((resolve) => setTimeout(resolve, 10));

    const session = await store.get("sid-1");
    expect(session).toBeUndefined();
  });

  test("valid session returns data", async () => {
    const store = new MemorySessionStore();
    await store.create("sid-1", "user-1", { role: "admin" }, 3600);

    const session = await store.get("sid-1");
    expect(session).toBeDefined();
    expect(session!.userId).toBe("user-1");
    expect(session!.data).toEqual({ role: "admin" });
  });

  test("deleteAllForUser removes all sessions", async () => {
    const store = new MemorySessionStore();
    await store.create("sid-1", "user-1", {}, 3600);
    await store.create("sid-2", "user-1", {}, 3600);
    await store.create("sid-3", "user-2", {}, 3600);

    await store.deleteAllForUser("user-1");

    expect(await store.get("sid-1")).toBeUndefined();
    expect(await store.get("sid-2")).toBeUndefined();
    // User-2 session should remain
    expect(await store.get("sid-3")).toBeDefined();
  });
});
