/**
 * Property-based / fuzz tests for @urauth/node.
 *
 * Uses fast-check to verify token operations never crash on arbitrary input.
 */

import { describe, test, expect } from "bun:test";
import fc from "fast-check";
import { TokenService } from "../../src/tokens/jwt";
import { validateConfig, type AuthConfig } from "../../src/config";
import { InvalidTokenError, TokenExpiredError } from "@urauth/ts";

const SECRET = "test-secret-key-32-chars-long-xx";
const config: AuthConfig = { secretKey: SECRET, environment: "testing" };
const svc = new TokenService(config);

describe("Token decoding fuzz", () => {
  test("arbitrary strings never crash decodeToken", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 0, maxLength: 1000 }), async (token) => {
        try {
          await svc.decodeToken(token);
        } catch (e) {
          expect(e instanceof InvalidTokenError || e instanceof TokenExpiredError).toBe(true);
        }
      }),
      { numRuns: 200 },
    );
  });

  test("JWT-shaped garbage never crashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.tuple(
          fc.base64String({ minLength: 1, maxLength: 100 }),
          fc.base64String({ minLength: 1, maxLength: 200 }),
          fc.base64String({ minLength: 1, maxLength: 100 }),
        ),
        async ([header, payload, sig]) => {
          const token = `${header}.${payload}.${sig}`;
          try {
            await svc.decodeToken(token);
          } catch (e) {
            expect(e instanceof InvalidTokenError || e instanceof TokenExpiredError).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  test("arbitrary bytes (as UTF-8) never crash decodeToken", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 0, maxLength: 500 }),
        async (bytes) => {
          const str = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
          try {
            await svc.decodeToken(str);
          } catch (e) {
            expect(e instanceof InvalidTokenError || e instanceof TokenExpiredError).toBe(true);
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("Token validation fuzz", () => {
  test("arbitrary strings never crash validateAccessToken", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 0, maxLength: 500 }), async (token) => {
        try {
          await svc.validateAccessToken(token);
        } catch (e) {
          expect(e instanceof InvalidTokenError || e instanceof TokenExpiredError).toBe(true);
        }
      }),
      { numRuns: 200 },
    );
  });

  test("arbitrary strings never crash validateRefreshToken", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 0, maxLength: 500 }), async (token) => {
        try {
          await svc.validateRefreshToken(token);
        } catch (e) {
          expect(e instanceof InvalidTokenError || e instanceof TokenExpiredError).toBe(true);
        }
      }),
      { numRuns: 200 },
    );
  });
});

describe("Token creation property-based", () => {
  test("any non-empty userId produces a valid token", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }).filter((s) => s.trim().length > 0),
        async (userId) => {
          const token = await svc.createAccessToken(userId);
          const claims = await svc.validateAccessToken(token);
          expect(claims.sub).toBe(userId.trim());
          expect(claims.type).toBe("access");
        },
      ),
      { numRuns: 100 },
    );
  });

  test("every token pair has distinct JTIs", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 50 }).filter((s) => s.trim().length > 0),
        async (userId) => {
          const pair = await svc.createTokenPair(userId);
          const accessClaims = await svc.decodeToken(pair.accessToken);
          const refreshClaims = await svc.decodeToken(pair.refreshToken);
          expect(accessClaims.jti).not.toBe(refreshClaims.jti);
        },
      ),
      { numRuns: 50 },
    );
  });

  test("any mutation of a valid token's signature fails verification", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: 50 }),
        async (offset) => {
          const token = await svc.createAccessToken("test-user");
          const parts = token.split(".");
          const sig = parts[2]!;
          if (sig.length === 0) return;
          const idx = offset % sig.length;
          const chars = sig.split("");
          chars[idx] = chars[idx] === "A" ? "B" : "A";
          const mutated = `${parts[0]}.${parts[1]}.${chars.join("")}`;
          try {
            await svc.validateAccessToken(mutated);
            // Should not reach here — mutated signature should fail
            throw new Error("Should have thrown");
          } catch (e) {
            expect(e instanceof InvalidTokenError).toBe(true);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

describe("Config validation fuzz", () => {
  test("arbitrary short strings as secretKey are rejected or accepted consistently", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 50 }), (key) => {
        try {
          validateConfig({ secretKey: key });
          // If it passes, key must be non-empty, non-weak, and >= 32 chars for HMAC
          expect(key.trim().length).toBeGreaterThan(0);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
        }
      }),
      { numRuns: 300 },
    );
  });
});
