import type { TokenStore } from "../stores/types";

/** Thin facade over TokenStore for token revocation. */
export class RevocationService {
  private store: TokenStore;

  constructor(store: TokenStore) {
    this.store = store;
  }

  async isRevoked(jti: string): Promise<boolean> {
    return this.store.isRevoked(jti);
  }

  async revoke(jti: string, expiresAt: number): Promise<void> {
    return this.store.revoke(jti, expiresAt);
  }

  async revokeAllForUser(userId: string): Promise<void> {
    return this.store.revokeAllForUser(userId);
  }
}
