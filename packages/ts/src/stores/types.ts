/** Protocol for token revocation storage. */
export interface TokenStore {
  isRevoked(jti: string): Promise<boolean>;
  revoke(jti: string, expiresAt: number): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
  addToken(
    jti: string,
    userId: string,
    tokenType: string,
    expiresAt: number,
    familyId?: string,
  ): Promise<void>;
  getFamilyId(jti: string): Promise<string | undefined>;
  revokeFamily(familyId: string): Promise<void>;
}

/** Protocol for server-side session storage. */
export interface SessionStore {
  create(
    sessionId: string,
    userId: string,
    data: Record<string, unknown>,
    ttl: number,
  ): Promise<void>;
  get(sessionId: string): Promise<SessionData | undefined>;
  delete(sessionId: string): Promise<void>;
  deleteAllForUser(userId: string): Promise<void>;
}

export interface SessionData {
  userId: string;
  data: Record<string, unknown>;
  expiresAt: number;
}
