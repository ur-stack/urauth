/** Configuration for urauth JWT verification and token management. */
export interface AuthConfig {
  /** Secret key or public key for JWT verification and signing. */
  secretKey: string;
  /** JWT algorithm (default: HS256). */
  algorithm?: string;
  /** Expected issuer claim. */
  issuer?: string;
  /** Expected audience claim. */
  audience?: string;
  /** Access token TTL in seconds (default: 900 = 15 min). */
  accessTokenTtl?: number;
  /** Refresh token TTL in seconds (default: 604800 = 7 days). */
  refreshTokenTtl?: number;
  /** Whether to rotate refresh tokens on use (default: true). */
  rotateRefreshTokens?: boolean;
  /** Session TTL in seconds (default: 86400 = 24 hours). */
  sessionTtl?: number;
}

export const defaultConfig: Partial<AuthConfig> = {
  algorithm: "HS256",
  accessTokenTtl: 900,
  refreshTokenTtl: 604_800,
  rotateRefreshTokens: true,
  sessionTtl: 86_400,
};
