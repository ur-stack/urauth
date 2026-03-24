import type { TokenStore, SessionStore, SessionData } from "./types";

interface TokenRecord {
  jti: string;
  userId: string;
  tokenType: string;
  expiresAt: number;
  familyId: string | undefined;
  revoked: boolean;
}

/** In-memory token store for development and testing. */
export class MemoryTokenStore implements TokenStore {
  private tokens = new Map<string, TokenRecord>();
  private userTokens = new Map<string, Set<string>>();

  async isRevoked(jti: string): Promise<boolean> {
    const rec = this.tokens.get(jti);
    return rec?.revoked ?? false;
  }

  async revoke(jti: string, _expiresAt: number): Promise<void> {
    const rec = this.tokens.get(jti);
    if (rec) rec.revoked = true;
  }

  async revokeAllForUser(userId: string): Promise<void> {
    for (const jti of this.userTokens.get(userId) ?? []) {
      const rec = this.tokens.get(jti);
      if (rec) rec.revoked = true;
    }
  }

  async addToken(
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
  }

  async getFamilyId(jti: string): Promise<string | undefined> {
    return this.tokens.get(jti)?.familyId;
  }

  async revokeFamily(familyId: string): Promise<void> {
    for (const rec of this.tokens.values()) {
      if (rec.familyId === familyId) rec.revoked = true;
    }
  }
}

/** In-memory session store for development and testing. */
export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, SessionData & { rawUserId: string }>();
  private userSessions = new Map<string, Set<string>>();

  async create(
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
  }

  async get(sessionId: string): Promise<SessionData | undefined> {
    const session = this.sessions.get(sessionId);
    if (!session) return undefined;
    if (Date.now() / 1000 > session.expiresAt) {
      this.sessions.delete(sessionId);
      return undefined;
    }
    return { userId: session.userId, data: session.data, expiresAt: session.expiresAt };
  }

  async delete(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.delete(sessionId);
      this.userSessions.get(session.rawUserId)?.delete(sessionId);
    }
  }

  async deleteAllForUser(userId: string): Promise<void> {
    for (const sid of this.userSessions.get(userId) ?? []) {
      this.sessions.delete(sid);
    }
    this.userSessions.delete(userId);
  }
}
