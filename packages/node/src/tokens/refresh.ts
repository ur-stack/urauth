import type { TokenStore } from "../stores/types";
import type { AuthConfig } from "../config";
import type { TokenPair } from "@urauth/ts";
import { TokenRevokedError } from "@urauth/ts";
import { TokenService } from "./jwt";

/** Handles refresh-token rotation with reuse detection. */
export class RefreshService {
  private tokens: TokenService;
  private store: TokenStore;

  constructor(tokenService: TokenService, tokenStore: TokenStore, _config: AuthConfig) {
    this.tokens = tokenService;
    this.store = tokenStore;
  }

  /**
   * Validate, revoke old token, issue new pair.
   *
   * If the old token was already revoked (reuse detected), revoke the
   * entire token family to mitigate stolen-token replay.
   */
  async rotate(rawRefreshToken: string): Promise<TokenPair> {
    const claims = await this.tokens.validateRefreshToken(rawRefreshToken);
    const jti = claims.jti as string;
    const userId = claims.sub as string;

    // Reuse detection: if already revoked, someone replayed a stolen token
    if (await this.store.isRevoked(jti)) {
      const familyId = await this.store.getFamilyId(jti);
      if (familyId) {
        await this.store.revokeFamily(familyId);
      } else {
        await this.store.revokeAllForUser(userId);
      }
      throw new TokenRevokedError("Refresh token reuse detected — all tokens revoked");
    }

    // Revoke the old refresh token
    await this.store.revoke(jti, claims.exp as number);

    // Issue new pair within the same family
    const familyId =
      (claims.family_id as string | undefined) ??
      (await this.store.getFamilyId(jti)) ??
      crypto.randomUUID().replace(/-/g, "");

    const pair = await this.tokens.createTokenPair(userId, { familyId });

    // Track the new tokens
    const accessClaims = await this.tokens.decodeToken(pair.accessToken);
    const refreshClaims = await this.tokens.decodeToken(pair.refreshToken);

    await this.store.addToken(
      accessClaims.jti as string,
      userId,
      "access",
      accessClaims.exp as number,
      familyId,
    );
    await this.store.addToken(
      refreshClaims.jti as string,
      userId,
      "refresh",
      refreshClaims.exp as number,
      familyId,
    );

    return pair;
  }
}
