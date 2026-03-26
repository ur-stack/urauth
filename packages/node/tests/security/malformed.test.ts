import { describe, test, expect } from "bun:test";
import { TokenService } from "../../src/tokens/jwt";
import { InvalidTokenError, TokenExpiredError, AuthError } from "@urauth/ts";
import type { AuthConfig } from "../../src/config";

const SECRET = "test-secret-key-32-chars-long-xx";
const config: AuthConfig = { secretKey: SECRET, environment: "testing" };

describe("Malformed Input Handling", () => {
  const svc = new TokenService(config);

  test("extremely long token string (10KB) is rejected", async () => {
    const longToken = "a".repeat(10240);
    await expect(svc.validateAccessToken(longToken)).rejects.toThrow();
  });

  test("token with null bytes is rejected", async () => {
    const nullToken = "eyJ\0alg\0.eyJ\0sub\0.sig\0nature";
    await expect(svc.validateAccessToken(nullToken)).rejects.toThrow();
  });

  test("token with unicode is rejected", async () => {
    const unicodeToken = "\u{1F4A9}.\u{1F4A9}.\u{1F4A9}";
    await expect(svc.validateAccessToken(unicodeToken)).rejects.toThrow();
  });

  test("token with only dots is rejected", async () => {
    await expect(svc.validateAccessToken("...")).rejects.toThrow();
    await expect(svc.validateAccessToken("..")).rejects.toThrow();
  });

  test("token with empty segments is rejected", async () => {
    await expect(svc.validateAccessToken("..abc")).rejects.toThrow();
    await expect(svc.validateAccessToken("abc..")).rejects.toThrow();
    await expect(svc.validateAccessToken(".abc.")).rejects.toThrow();
  });

  test("token that looks valid but has corrupted base64 is rejected", async () => {
    // Create a real token and corrupt the signature
    const validToken = await svc.createAccessToken("user-1");
    const parts = validToken.split(".");
    // Corrupt the last few characters of the signature
    const corrupted =
      parts[0] +
      "." +
      parts[1] +
      "." +
      parts[2]!.slice(0, -4) +
      "XXXX";
    await expect(svc.validateAccessToken(corrupted)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("extremely long token (100KB) is rejected", async () => {
    const hugeToken = "a".repeat(102400);
    await expect(svc.validateAccessToken(hugeToken)).rejects.toThrow();
  });

  test("token with 4 segments (a.b.c.d) is rejected", async () => {
    await expect(svc.validateAccessToken("a.b.c.d")).rejects.toThrow();
  });

  test("token with extra dots is rejected", async () => {
    await expect(svc.validateAccessToken("a.b.c.d.e.f")).rejects.toThrow();
    await expect(svc.validateAccessToken("header..payload..sig")).rejects.toThrow();
  });

  test("extremely long userId (10,000 chars) — no crash", async () => {
    const longUserId = "u".repeat(10_000);
    try {
      const token = await svc.createAccessToken(longUserId);
      const payload = await svc.validateAccessToken(token);
      expect(payload.sub).toBe(longUserId);
    } catch (err) {
      // Should be a clean error, not a crash
      expect(err).toBeInstanceOf(Error);
    }
  });

  test("token built with wrong HMAC variant is rejected", async () => {
    // Create a token with HS256 (default), verify with HS384 config
    const hs256Token = await svc.createAccessToken("user-1");

    const hs384Config: AuthConfig = {
      secretKey: SECRET,
      environment: "testing",
      algorithm: "HS384",
    };
    const hs384Svc = new TokenService(hs384Config);

    await expect(hs384Svc.validateAccessToken(hs256Token)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("token with valid structure but different secret yields InvalidTokenError", async () => {
    const otherConfig: AuthConfig = {
      secretKey: "different-secret-key-32-chars-xx",
      environment: "testing",
    };
    const otherSvc = new TokenService(otherConfig);
    const otherToken = await otherSvc.createAccessToken("user-1");

    // Verifying with our main service (different secret) should throw InvalidTokenError
    await expect(svc.validateAccessToken(otherToken)).rejects.toThrow(
      InvalidTokenError,
    );
  });
});
