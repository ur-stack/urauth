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
  /** Environment mode (default: "development"). */
  environment?: "development" | "production" | "testing";
  /** Allow insecure secret keys (default: false). Only for development/testing. */
  allowInsecureKey?: boolean;
}

export const defaultConfig: Partial<AuthConfig> = {
  algorithm: "HS256",
  accessTokenTtl: 900,
  refreshTokenTtl: 604_800,
  rotateRefreshTokens: true,
  sessionTtl: 86_400,
  environment: "development",
  allowInsecureKey: false,
};

const DEFAULT_KEY = "CHANGE-ME-IN-PRODUCTION";
const MIN_HMAC_KEY_LENGTH = 32;
const HMAC_ALGORITHMS = new Set(["HS256", "HS384", "HS512"]);
const WEAK_SECRETS = new Set([
  "secret",
  "password",
  "changeme",
  "test",
  "key",
  "admin",
  "123456",
  "jwt-secret",
  "my-secret",
  "super-secret",
]);

/**
 * Validate an AuthConfig for security. Call this when creating
 * a TokenService or Auth instance to enforce key safety.
 *
 * @throws {Error} if the config has insecure values in production
 */
export function validateConfig(config: AuthConfig): void {
  const env = config.environment ?? defaultConfig.environment ?? "development";
  const allowInsecure = config.allowInsecureKey ?? (env === "testing");
  const algorithm = config.algorithm ?? defaultConfig.algorithm ?? "HS256";

  // Reject empty / whitespace-only keys unconditionally
  if (!config.secretKey || !config.secretKey.trim()) {
    throw new Error("urauth: secretKey must not be empty or whitespace-only.");
  }

  // Default key check
  if (config.secretKey === DEFAULT_KEY) {
    if (!allowInsecure) {
      throw new Error(
        `urauth: secretKey is the default "${DEFAULT_KEY}". ` +
        "Set a strong secret or pass allowInsecureKey: true for development.",
      );
    }
    if (env === "production") {
      throw new Error(
        "urauth: default secretKey is not allowed in production.",
      );
    }
  }

  // Production rejects allowInsecureKey
  if (env === "production" && config.allowInsecureKey) {
    throw new Error(
      "urauth: allowInsecureKey cannot be true in production.",
    );
  }

  // HMAC minimum key length
  if (HMAC_ALGORITHMS.has(algorithm) && config.secretKey.length < MIN_HMAC_KEY_LENGTH) {
    if (!allowInsecure) {
      throw new Error(
        `urauth: secretKey must be at least ${MIN_HMAC_KEY_LENGTH} characters for ${algorithm}. ` +
        "Set allowInsecureKey: true for development.",
      );
    }
  }

  // Weak secret detection
  if (WEAK_SECRETS.has(config.secretKey.toLowerCase().trim())) {
    if (!allowInsecure) {
      throw new Error(
        "urauth: secretKey is trivially weak. Use a strong random key.",
      );
    }
  }
}
