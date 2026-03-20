/** Configuration for urauth JWT verification. */
export interface AuthConfig {
  /** Secret key or public key for JWT verification. */
  secretKey: string;
  /** JWT algorithm (default: HS256). */
  algorithm?: string;
  /** Expected issuer claim. */
  issuer?: string;
  /** Expected audience claim. */
  audience?: string;
}

export const defaultConfig: Partial<AuthConfig> = {
  algorithm: "HS256",
};
