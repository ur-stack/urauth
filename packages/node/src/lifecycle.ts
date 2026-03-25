/**
 * TokenLifecycle — orchestrates token issuance, refresh, revocation, and validation.
 *
 * Combines TokenService, RefreshService, and RevocationService into a single API.
 */

import type { TokenPayload, TokenPair } from "@urauth/ts";
import type { AuthConfig } from "./config";
import type { TokenStore } from "./stores/types";
import { TokenService, type CreateAccessTokenOptions } from "./tokens/jwt";
import { RefreshService } from "./tokens/refresh";
import { RevocationService } from "./tokens/revocation";

export interface IssueRequest extends CreateAccessTokenOptions {
  userId: string;
  familyId?: string;
}

export interface IssuedTokenPair extends TokenPair {
  /** Decoded access token payload for convenience. */
  payload: TokenPayload;
}

export class TokenLifecycle {
  private tokenService: TokenService;
  private refreshService: RefreshService;
  private revocationService: RevocationService;
  private store: TokenStore;

  constructor(config: AuthConfig, store: TokenStore) {
    this.tokenService = new TokenService(config);
    this.refreshService = new RefreshService(this.tokenService, store, config);
    this.revocationService = new RevocationService(store);
    this.store = store;
  }

  /** Issue a new access + refresh token pair. */
  async issue(request: IssueRequest): Promise<IssuedTokenPair> {
    const { userId, familyId, ...opts } = request;
    const pair = await this.tokenService.createTokenPair(userId, { ...opts, familyId });

    // Track tokens in store
    const accessClaims = await this.tokenService.decodeToken(pair.accessToken);
    const refreshClaims = await this.tokenService.decodeToken(pair.refreshToken);
    const fam = familyId ?? (refreshClaims.family_id as string | undefined);

    await this.store.addToken(
      accessClaims.jti as string,
      userId,
      "access",
      accessClaims.exp as number,
      fam,
    );
    await this.store.addToken(
      refreshClaims.jti as string,
      userId,
      "refresh",
      refreshClaims.exp as number,
      fam,
    );

    return {
      ...pair,
      payload: accessClaims as unknown as TokenPayload,
    };
  }

  /** Rotate a refresh token — validates, revokes old, issues new pair. */
  async refresh(rawRefreshToken: string): Promise<TokenPair> {
    return this.refreshService.rotate(rawRefreshToken);
  }

  /** Revoke a single token by its raw JWT string. */
  async revoke(rawToken: string): Promise<void> {
    const claims = await this.tokenService.decodeToken(rawToken);
    await this.revocationService.revoke(claims.jti as string, claims.exp as number);
  }

  /** Revoke all tokens for a user. */
  async revokeAll(userId: string): Promise<void> {
    await this.revocationService.revokeAllForUser(userId);
  }

  /** Validate an access token — verifies signature, expiry, and revocation. */
  async validate(rawAccessToken: string): Promise<TokenPayload> {
    const payload = await this.tokenService.validateAccessToken(rawAccessToken);
    if (await this.revocationService.isRevoked(payload.jti)) {
      const { TokenRevokedError } = await import("@urauth/ts");
      throw new TokenRevokedError();
    }
    return payload;
  }
}
