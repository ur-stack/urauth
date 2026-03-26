import type { TokenStore, SessionStore, SessionData } from "./types";

interface TokenRecord {
  jti: string;
  userId: string;
  tokenType: string;
  expiresAt: number;
  familyId: string | undefined;
  revoked: boolean;
}

/**
 * In-memory token store for development and testing.
 *
 * With `strict: true` (default), unknown JTIs are treated as revoked
 * (fail-closed). Set `strict: false` only if your flow does not call
 * `addToken()` before checking revocation.
 */
export class MemoryTokenStore implements TokenStore {
  private tokens = new Map<string, TokenRecord>();
  private userTokens = new Map<string, Set<string>>();
  private strict: boolean;

  constructor(opts?: { strict?: boolean }) {
    this.strict = opts?.strict ?? true;
  }

  isRevoked(jti: string): Promise<boolean> {
    const rec = this.tokens.get(jti);
    if (!rec) return Promise.resolve(this.strict);
    return Promise.resolve(rec.revoked);
  }

  revoke(jti: string, _expiresAt: number): Promise<void> {
    const rec = this.tokens.get(jti);
    if (rec) rec.revoked = true;
    return Promise.resolve();
  }

  revokeAllForUser(userId: string): Promise<void> {
    for (const jti of this.userTokens.get(userId) ?? []) {
      const rec = this.tokens.get(jti);
      if (rec) rec.revoked = true;
    }
    return Promise.resolve();
  }

  addToken(
    jti: string,
    userId: string,
    tokenType: string,
    expiresAt: number,
    familyId?: string,
  ): Promise<void> {
    this.tokens.set(jti, {
      jti,
      userId,
      tokenType,
      expiresAt,
      familyId,
      revoked: false,
    });
    let set = this.userTokens.get(userId);
    if (!set) {
      set = new Set();
      this.userTokens.set(userId, set);
    }
    set.add(jti);
    return Promise.resolve();
  }

  getFamilyId(jti: string): Promise<string | undefined> {
    return Promise.resolve(this.tokens.get(jti)?.familyId);
  }

  revokeFamily(familyId: string): Promise<void> {
    for (const rec of this.tokens.values()) {
      if (rec.familyId === familyId) rec.revoked = true;
    }
    return Promise.resolve();
  }
}

/** In-memory session store for development and testing. */
export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, SessionData & { rawUserId: string }>();
  private userSessions = new Map<string, Set<string>>();

  create(
    sessionId: string,
    userId: string,
    data: Record<string, unknown>,
    ttl: number,
  ): Promise<void> {
    this.sessions.set(sessionId, {
      userId,
      data,
      expiresAt: Date.now() / 1000 + ttl,
      rawUserId: userId,
    });
    let set = this.userSessions.get(userId);
    if (!set) {
      set = new Set();
      this.userSessions.set(userId, set);
    }
    set.add(sessionId);
    return Promise.resolve();
  }

  get(sessionId: string): Promise<SessionData | undefined> {
    const session = this.sessions.get(sessionId);
    if (!session) return Promise.resolve(undefined);
    if (Date.now() / 1000 > session.expiresAt) {
      this.sessions.delete(sessionId);
      return Promise.resolve(undefined);
    }
    return Promise.resolve({ userId: session.userId, data: session.data, expiresAt: session.expiresAt });
  }

  delete(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.delete(sessionId);
      this.userSessions.get(session.rawUserId)?.delete(sessionId);
    }
    return Promise.resolve();
  }

  deleteAllForUser(userId: string): Promise<void> {
    for (const sid of this.userSessions.get(userId) ?? []) {
      this.sessions.delete(sid);
    }
    this.userSessions.delete(userId);
    return Promise.resolve();
  }
}
