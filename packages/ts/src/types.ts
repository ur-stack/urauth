/** Decoded JWT claims. */
export interface TokenPayload {
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  type: "access" | "refresh";
  scopes?: string[];
  roles?: string[];
  permissions?: string[];
  tenant_id?: string;
  fresh?: boolean;
  family_id?: string;
  [key: string]: unknown;
}

/** Access + refresh token pair. */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
}
