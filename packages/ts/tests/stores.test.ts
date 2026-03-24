import { describe, test, expect } from "bun:test";
import { MemoryTokenStore, MemorySessionStore } from "../src/index";

describe("MemoryTokenStore", () => {
  test("addToken and isRevoked", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    expect(await store.isRevoked("jti-1")).toBe(false);
  });

  test("revoke marks token as revoked", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.revoke("jti-1", Date.now() / 1000 + 3600);
    expect(await store.isRevoked("jti-1")).toBe(true);
  });

  test("revokeAllForUser revokes all user tokens", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600);
    await store.addToken("jti-2", "user-1", "refresh", Date.now() / 1000 + 3600);
    await store.addToken("jti-3", "user-2", "access", Date.now() / 1000 + 3600);
    await store.revokeAllForUser("user-1");
    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(true);
    expect(await store.isRevoked("jti-3")).toBe(false);
  });

  test("getFamilyId returns family", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "refresh", Date.now() / 1000 + 3600, "family-a");
    expect(await store.getFamilyId("jti-1")).toBe("family-a");
    expect(await store.getFamilyId("jti-nonexistent")).toBeUndefined();
  });

  test("revokeFamily revokes all tokens in family", async () => {
    const store = new MemoryTokenStore();
    await store.addToken("jti-1", "user-1", "access", Date.now() / 1000 + 3600, "family-a");
    await store.addToken("jti-2", "user-1", "refresh", Date.now() / 1000 + 3600, "family-a");
    await store.addToken("jti-3", "user-1", "access", Date.now() / 1000 + 3600, "family-b");
    await store.revokeFamily("family-a");
    expect(await store.isRevoked("jti-1")).toBe(true);
    expect(await store.isRevoked("jti-2")).toBe(true);
    expect(await store.isRevoked("jti-3")).toBe(false);
  });
});

describe("MemorySessionStore", () => {
  test("create and get session", async () => {
    const store = new MemorySessionStore();
    await store.create("sess-1", "user-1", { foo: "bar" }, 3600);
    const session = await store.get("sess-1");
    expect(session).toBeDefined();
    expect(session!.userId).toBe("user-1");
    expect(session!.data).toEqual({ foo: "bar" });
  });

  test("get returns undefined for nonexistent session", async () => {
    const store = new MemorySessionStore();
    expect(await store.get("nonexistent")).toBeUndefined();
  });

  test("get returns undefined for expired session", async () => {
    const store = new MemorySessionStore();
    await store.create("sess-1", "user-1", {}, 0); // TTL=0, already expired
    // Small delay to ensure expiry
    await new Promise((r) => setTimeout(r, 10));
    expect(await store.get("sess-1")).toBeUndefined();
  });

  test("delete removes session", async () => {
    const store = new MemorySessionStore();
    await store.create("sess-1", "user-1", {}, 3600);
    await store.delete("sess-1");
    expect(await store.get("sess-1")).toBeUndefined();
  });

  test("deleteAllForUser removes all user sessions", async () => {
    const store = new MemorySessionStore();
    await store.create("sess-1", "user-1", {}, 3600);
    await store.create("sess-2", "user-1", {}, 3600);
    await store.create("sess-3", "user-2", {}, 3600);
    await store.deleteAllForUser("user-1");
    expect(await store.get("sess-1")).toBeUndefined();
    expect(await store.get("sess-2")).toBeUndefined();
    expect(await store.get("sess-3")).toBeDefined();
  });
});
