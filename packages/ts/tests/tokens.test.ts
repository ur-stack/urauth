import { describe, test, expect } from "bun:test";
import {
  TokenService,
  verifyToken,
  type AuthConfig,
  type TokenPayload,
} from "../src/index";

const config: AuthConfig = {
  secretKey: "test-secret-key-for-unit-tests-only",
  algorithm: "HS256",
  accessTokenTtl: 900,
  refreshTokenTtl: 604_800,
};

describe("TokenService", () => {
  const service = new TokenService(config);

  test("createAccessToken returns a JWT string", async () => {
    const token = await service.createAccessToken("user-1");
    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);
  });

  test("createAccessToken includes correct claims", async () => {
    const token = await service.createAccessToken("user-1", {
      roles: ["admin"],
      scopes: ["read", "write"],
      tenantId: "tenant-1",
      fresh: true,
      extraClaims: { custom: "value" },
    });
    const payload = await service.validateAccessToken(token);
    expect(payload.sub).toBe("user-1");
    expect(payload.type).toBe("access");
    expect(payload.roles).toEqual(["admin"]);
    expect(payload.scopes).toEqual(["read", "write"]);
    expect(payload.tenant_id).toBe("tenant-1");
    expect(payload.fresh).toBe(true);
    expect(payload.custom).toBe("value");
  });

  test("createRefreshToken has type refresh", async () => {
    const token = await service.createRefreshToken("user-1", {
      familyId: "family-abc",
    });
    const claims = await service.validateRefreshToken(token);
    expect(claims.type).toBe("refresh");
    expect(claims.sub).toBe("user-1");
    expect(claims.family_id).toBe("family-abc");
  });

  test("createTokenPair returns both tokens", async () => {
    const pair = await service.createTokenPair("user-1");
    expect(pair.tokenType).toBe("bearer");
    expect(pair.accessToken.split(".")).toHaveLength(3);
    expect(pair.refreshToken.split(".")).toHaveLength(3);

    const access = await service.validateAccessToken(pair.accessToken);
    expect(access.type).toBe("access");

    const refresh = await service.validateRefreshToken(pair.refreshToken);
    expect(refresh.type).toBe("refresh");
  });

  test("validateAccessToken rejects refresh tokens", async () => {
    const token = await service.createRefreshToken("user-1");
    expect(service.validateAccessToken(token)).rejects.toThrow("Not an access token");
  });

  test("validateRefreshToken rejects access tokens", async () => {
    const token = await service.createAccessToken("user-1");
    expect(service.validateRefreshToken(token)).rejects.toThrow("Not a refresh token");
  });

  test("decodeToken returns raw claims", async () => {
    const token = await service.createAccessToken("user-1");
    const claims = await service.decodeToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.jti).toBeDefined();
    expect(claims.iat).toBeDefined();
    expect(claims.exp).toBeDefined();
  });
});

describe("verifyToken (standalone)", () => {
  const service = new TokenService(config);

  test("verifies a valid token", async () => {
    const token = await service.createAccessToken("user-1");
    const payload = await verifyToken(token, config);
    expect(payload.sub).toBe("user-1");
  });

  test("rejects token with wrong secret", async () => {
    const token = await service.createAccessToken("user-1");
    const badConfig: AuthConfig = { ...config, secretKey: "wrong-key" };
    expect(verifyToken(token, badConfig)).rejects.toThrow();
  });
});

describe("TokenService with issuer/audience", () => {
  const configWithIssAud: AuthConfig = {
    ...config,
    issuer: "urauth",
    audience: "my-app",
  };
  const service = new TokenService(configWithIssAud);

  test("includes iss and aud claims", async () => {
    const token = await service.createAccessToken("user-1");
    const claims = await service.decodeToken(token);
    expect(claims.iss).toBe("urauth");
    expect(claims.aud).toBe("my-app");
  });
});
