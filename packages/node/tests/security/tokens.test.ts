import { describe, test, expect } from "bun:test";
import { TokenService } from "../../src/tokens/jwt";
import { InvalidTokenError, TokenExpiredError } from "@urauth/ts";
import type { AuthConfig } from "../../src/config";

const SECRET = "test-secret-key-32-chars-long-xx";
const config: AuthConfig = { secretKey: SECRET, environment: "testing" };

describe("Token Security", () => {
  test("token with wrong secret key is rejected", async () => {
    const svc1 = new TokenService(config);
    const svc2 = new TokenService({
      secretKey: "different-secret-key-32-chars-xx",
      environment: "testing",
    });

    const token = await svc1.createAccessToken("user-1");
    await expect(svc2.validateAccessToken(token)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("empty string token is rejected with InvalidTokenError", async () => {
    const svc = new TokenService(config);
    await expect(svc.validateAccessToken("")).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test('garbage token "aaaa.bbbb.cccc" is rejected', async () => {
    const svc = new TokenService(config);
    await expect(svc.validateAccessToken("aaaa.bbbb.cccc")).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("token with extra dots is rejected", async () => {
    const svc = new TokenService(config);
    await expect(
      svc.validateAccessToken("a.b.c.d.e"),
    ).rejects.toThrow(InvalidTokenError);
  });

  test("refresh token rejected by validateAccessToken", async () => {
    const svc = new TokenService(config);
    const refresh = await svc.createRefreshToken("user-1");
    await expect(svc.validateAccessToken(refresh)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("access token rejected by validateRefreshToken", async () => {
    const svc = new TokenService(config);
    const access = await svc.createAccessToken("user-1");
    await expect(svc.validateRefreshToken(access)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("empty userId is rejected", async () => {
    const svc = new TokenService(config);
    await expect(svc.createAccessToken("")).rejects.toThrow(
      "userId must be a non-empty string",
    );
  });

  test("whitespace-only userId is rejected", async () => {
    const svc = new TokenService(config);
    await expect(svc.createAccessToken("   ")).rejects.toThrow(
      "userId must be a non-empty string",
    );
  });

  test("extra claims cannot override reserved claims", async () => {
    const svc = new TokenService(config);
    const token = await svc.createAccessToken("user-1", {
      extraClaims: {
        sub: "evil-user",
        jti: "evil-jti",
        iat: 0,
        exp: 9999999999,
        type: "refresh",
        iss: "evil-issuer",
        aud: "evil-audience",
      },
    });

    const claims = await svc.decodeToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.jti).not.toBe("evil-jti");
    expect(claims.iat).not.toBe(0);
    expect(claims.exp).not.toBe(9999999999);
    expect(claims.type).toBe("access");
    expect(claims.iss).not.toBe("evil-issuer");
    expect(claims.aud).not.toBe("evil-audience");
  });

  test("token pair has unique JTIs", async () => {
    const svc = new TokenService(config);
    const pair = await svc.createTokenPair("user-1");
    const accessClaims = await svc.decodeToken(pair.accessToken);
    const refreshClaims = await svc.decodeToken(pair.refreshToken);
    expect(accessClaims.jti).not.toBe(refreshClaims.jti);
  });

  test("token pair has same userId", async () => {
    const svc = new TokenService(config);
    const pair = await svc.createTokenPair("user-1");
    const accessClaims = await svc.decodeToken(pair.accessToken);
    const refreshClaims = await svc.decodeToken(pair.refreshToken);
    expect(accessClaims.sub).toBe("user-1");
    expect(refreshClaims.sub).toBe("user-1");
  });

  test("expired access token is rejected", async () => {
    const svc = new TokenService({
      ...config,
      accessTokenTtl: -1,
    });
    const token = await svc.createAccessToken("user-1");
    await expect(svc.validateAccessToken(token)).rejects.toThrow(
      TokenExpiredError,
    );
  });

  test("expired refresh token is rejected", async () => {
    const svc = new TokenService({
      ...config,
      refreshTokenTtl: -1,
    });
    const token = await svc.createRefreshToken("user-1");
    await expect(svc.validateRefreshToken(token)).rejects.toThrow(
      TokenExpiredError,
    );
  });

  test("issuer mismatch is rejected", async () => {
    const svcA = new TokenService({ ...config, issuer: "app-a" });
    const svcB = new TokenService({ ...config, issuer: "app-b" });

    const token = await svcA.createAccessToken("user-1");
    await expect(svcB.validateAccessToken(token)).rejects.toThrow(
      InvalidTokenError,
    );
  });

  test("audience mismatch is rejected", async () => {
    const svcA = new TokenService({ ...config, audience: "aud-a" });
    const svcB = new TokenService({ ...config, audience: "aud-b" });

    const token = await svcA.createAccessToken("user-1");
    await expect(svcB.validateAccessToken(token)).rejects.toThrow(
      InvalidTokenError,
    );
  });
});
