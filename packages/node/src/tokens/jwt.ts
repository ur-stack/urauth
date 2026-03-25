import * as jose from "jose";
import type { AuthConfig } from "../config";
import { defaultConfig, validateConfig } from "../config";
import { InvalidTokenError, TokenExpiredError } from "@urauth/ts";
import type { TokenPayload, TokenPair } from "@urauth/ts";

/**
 * Verify and decode a JWT token.
 *
 * @param token - The JWT string to verify
 * @param config - Auth configuration with secret key and options
 * @returns Decoded token payload
 */
export async function verifyToken(
  token: string,
  config: AuthConfig,
): Promise<TokenPayload> {
  const algorithm = config.algorithm ?? "HS256";
  const secret = new TextEncoder().encode(config.secretKey);

  try {
    const { payload } = await jose.jwtVerify(token, secret, {
      algorithms: [algorithm],
      issuer: config.issuer,
      audience: config.audience,
    });

    return payload as unknown as TokenPayload;
  } catch (err) {
    if (err instanceof jose.errors.JWTExpired) {
      throw new TokenExpiredError();
    }
    throw new InvalidTokenError(
      err instanceof Error ? err.message : "Invalid token",
    );
  }
}

export interface CreateAccessTokenOptions {
  scopes?: string[];
  roles?: string[];
  tenantId?: string;
  tenantPath?: Record<string, string>;
  fresh?: boolean;
  extraClaims?: Record<string, unknown>;
}

export interface CreateRefreshTokenOptions {
  familyId?: string;
}

export interface CreateTokenPairOptions extends CreateAccessTokenOptions {
  familyId?: string;
}

/** Create and validate JWTs using jose. */
export class TokenService {
  private config: AuthConfig;
  private secret: Uint8Array;

  constructor(config: AuthConfig) {
    validateConfig(config);
    this.config = config;
    this.secret = new TextEncoder().encode(config.secretKey);
  }

  private get algorithm(): string {
    return this.config.algorithm ?? defaultConfig.algorithm ?? "HS256";
  }

  private get accessTtl(): number {
    return this.config.accessTokenTtl ?? defaultConfig.accessTokenTtl ?? 900;
  }

  private get refreshTtl(): number {
    return this.config.refreshTokenTtl ?? defaultConfig.refreshTokenTtl ?? 604_800;
  }

  private baseClaims(
    userId: string,
    tokenType: string,
    ttl: number,
  ): Record<string, unknown> {
    const uid = String(userId).trim();
    if (!uid) {
      throw new Error("userId must be a non-empty string");
    }
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      sub: uid,
      jti: crypto.randomUUID().replace(/-/g, ""),
      iat: now,
      exp: now + ttl,
      type: tokenType,
    };
    if (this.config.issuer) claims.iss = this.config.issuer;
    if (this.config.audience) claims.aud = this.config.audience;
    return claims;
  }

  private async sign(claims: Record<string, unknown>): Promise<string> {
    const jwt = new jose.SignJWT(claims as jose.JWTPayload)
      .setProtectedHeader({ alg: this.algorithm });
    return jwt.sign(this.secret);
  }

  /** Create a signed access token. */
  async createAccessToken(
    userId: string,
    opts?: CreateAccessTokenOptions,
  ): Promise<string> {
    const claims = this.baseClaims(userId, "access", this.accessTtl);
    if (opts?.scopes) claims.scopes = opts.scopes;
    if (opts?.roles) claims.roles = opts.roles;
    if (opts?.tenantPath) {
      claims.tenant_path = opts.tenantPath;
      // Backward compat: also set flat tenant_id to last value
      const values = Object.values(opts.tenantPath);
      if (values.length > 0) claims.tenant_id = values[values.length - 1];
    } else if (opts?.tenantId) {
      claims.tenant_id = opts.tenantId;
    }
    if (opts?.fresh) claims.fresh = true;
    if (opts?.extraClaims) {
      const reserved = new Set(["sub", "jti", "iat", "exp", "iss", "aud", "type"]);
      for (const [key, value] of Object.entries(opts.extraClaims)) {
        if (!reserved.has(key)) {
          claims[key] = value;
        }
      }
    }
    return this.sign(claims);
  }

  /** Create a signed refresh token. */
  async createRefreshToken(
    userId: string,
    opts?: CreateRefreshTokenOptions,
  ): Promise<string> {
    const claims = this.baseClaims(userId, "refresh", this.refreshTtl);
    if (opts?.familyId) claims.family_id = opts.familyId;
    return this.sign(claims);
  }

  /** Create an access + refresh token pair. */
  async createTokenPair(
    userId: string,
    opts?: CreateTokenPairOptions,
  ): Promise<TokenPair> {
    const accessToken = await this.createAccessToken(userId, opts);
    const refreshToken = await this.createRefreshToken(userId, {
      familyId: opts?.familyId,
    });
    return { accessToken, refreshToken, tokenType: "bearer" };
  }

  /** Decode and verify a JWT, returning raw claims. */
  async decodeToken(token: string): Promise<Record<string, unknown>> {
    try {
      const { payload } = await jose.jwtVerify(token, this.secret, {
        algorithms: [this.algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
      });
      return payload as Record<string, unknown>;
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) {
        throw new TokenExpiredError();
      }
      throw new InvalidTokenError(
        err instanceof Error ? err.message : "Invalid token",
      );
    }
  }

  /** Decode, verify, and return a typed TokenPayload for an access token. */
  async validateAccessToken(token: string): Promise<TokenPayload> {
    const claims = await this.decodeToken(token);
    if (claims.type !== "access") {
      throw new InvalidTokenError("Not an access token");
    }
    return claims as unknown as TokenPayload;
  }

  /** Decode and verify a refresh token, returning raw claims. */
  async validateRefreshToken(token: string): Promise<Record<string, unknown>> {
    const claims = await this.decodeToken(token);
    if (claims.type !== "refresh") {
      throw new InvalidTokenError("Not a refresh token");
    }
    return claims;
  }
}
