import * as jose from "jose";
import type { AuthConfig } from "../config";
import { InvalidTokenError, TokenExpiredError } from "../exceptions";
import type { TokenPayload } from "../types";

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
