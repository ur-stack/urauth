/**
 * UrAuthClient — API client that bridges frontend with the urauth backend.
 *
 * Handles login/logout/refresh, token storage, auto-refresh on 401,
 * and builds AuthContext from decoded JWT claims.
 */

import { AuthContext } from "../context.js";
import { Permission, Role } from "../authz/primitives.js";
import type { TokenPair } from "../types.js";
import { type HttpClient, HttpError, createAxiosClient, type RequestConfig, type HttpResponse } from "./http.js";
import { type TokenStorage, memoryStorage, decodeJWT } from "./token.js";

export interface LoginRequest {
  username: string;
  password: string;
}

export interface IdentifierLoginRequest {
  identifier: string;
  password: string;
}

export type LoginCredentials = LoginRequest | IdentifierLoginRequest;

export interface UrAuthClientConfig {
  /** Base URL of the backend (e.g. "http://localhost:8000"). */
  baseURL: string;
  /** Auth route prefix (default: "/auth"). */
  authPrefix?: string;
  /** Custom HTTP client — defaults to axios. */
  httpClient?: HttpClient;
  /** Token persistence strategy — defaults to memoryStorage(). */
  storage?: TokenStorage;
  /** Called whenever tokens change (login/refresh/logout). */
  onTokenChange?: (tokens: TokenPair | null) => void;
  /** Automatically refresh on 401 responses (default: true). */
  autoRefresh?: boolean;
}

export class UrAuthClient {
  private readonly http: HttpClient;
  private readonly storage: TokenStorage;
  private readonly authPrefix: string;
  private readonly autoRefresh: boolean;
  onTokenChange?: (tokens: TokenPair | null) => void;
  private refreshPromise: Promise<TokenPair> | null = null;

  constructor(config: UrAuthClientConfig) {
    this.http = config.httpClient ?? createAxiosClient(config.baseURL);
    this.storage = config.storage ?? memoryStorage();
    this.authPrefix = config.authPrefix ?? "/auth";
    this.autoRefresh = config.autoRefresh ?? true;
    this.onTokenChange = config.onTokenChange;
  }

  // ── Auth endpoints ────────────────────────────────────────────

  async login(credentials: LoginCredentials): Promise<TokenPair> {
    const res = await this.http.request<{
      access_token: string;
      refresh_token: string;
      token_type: string;
    }>({
      method: "POST",
      url: `${this.authPrefix}/login`,
      data: credentials,
    });

    const pair: TokenPair = {
      accessToken: res.data.access_token,
      refreshToken: res.data.refresh_token,
      tokenType: res.data.token_type,
    };

    this.storage.setTokens(pair.accessToken, pair.refreshToken);
    this.onTokenChange?.(pair);
    return pair;
  }

  async refresh(): Promise<TokenPair> {
    // Deduplicate concurrent refresh calls
    if (this.refreshPromise !== null) return this.refreshPromise;

    const refreshToken = this.storage.getRefreshToken();
    if (refreshToken === null) {
      throw new Error("No refresh token available");
    }

    this.refreshPromise = this.http
      .request<{
        access_token: string;
        refresh_token: string;
        token_type: string;
      }>({
        method: "POST",
        url: `${this.authPrefix}/refresh`,
        data: { refresh_token: refreshToken },
      })
      .then((res) => {
        const pair: TokenPair = {
          accessToken: res.data.access_token,
          refreshToken: res.data.refresh_token,
          tokenType: res.data.token_type,
        };
        this.storage.setTokens(pair.accessToken, pair.refreshToken);
        this.onTokenChange?.(pair);
        return pair;
      })
      .finally(() => {
        this.refreshPromise = null;
      });

    return this.refreshPromise;
  }

  async logout(): Promise<void> {
    const token = this.storage.getAccessToken();
    if (token !== null) {
      try {
        await this.http.request({
          method: "POST",
          url: `${this.authPrefix}/logout`,
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Best-effort — clear local state regardless
      }
    }
    this.storage.clear();
    this.onTokenChange?.(null);
  }

  async logoutAll(): Promise<void> {
    const token = this.storage.getAccessToken();
    if (token !== null) {
      try {
        await this.http.request({
          method: "POST",
          url: `${this.authPrefix}/logout-all`,
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Best-effort
      }
    }
    this.storage.clear();
    this.onTokenChange?.(null);
  }

  // ── Token introspection ───────────────────────────────────────

  /** Decode the stored JWT and build an AuthContext with roles/permissions. */
  getContext(): AuthContext {
    const token = this.storage.getAccessToken();
    if (token === null) return AuthContext.anonymous();

    try {
      const payload = decodeJWT(token);

      // Check expiry
      if (payload.exp * 1000 < Date.now()) {
        return AuthContext.anonymous();
      }

      return new AuthContext({
        user: { id: payload.sub },
        roles: (payload.roles ?? []).map((r) => new Role(r)),
        permissions: (payload.permissions ?? []).map((p) => new Permission(p)),
        token: payload,
        authenticated: true,
      });
    } catch {
      return AuthContext.anonymous();
    }
  }

  isAuthenticated(): boolean {
    const token = this.storage.getAccessToken();
    if (token === null) return false;
    try {
      const payload = decodeJWT(token);
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  getAccessToken(): string | null {
    return this.storage.getAccessToken();
  }

  // ── Authenticated HTTP requests ───────────────────────────────

  /** Make an authenticated request. Retries once with a refreshed token on 401. */
  async request<T>(config: RequestConfig): Promise<HttpResponse<T>> {
    const token = this.storage.getAccessToken();
    const headers = { ...config.headers };
    if (token !== null) {
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      return await this.http.request<T>({ ...config, headers });
    } catch (err) {
      if (
        this.autoRefresh &&
        err instanceof HttpError &&
        err.status === 401 &&
        this.storage.getRefreshToken() !== null
      ) {
        const pair = await this.refresh();
        const retryHeaders = {
          ...config.headers,
          Authorization: `Bearer ${pair.accessToken}`,
        };
        return this.http.request<T>({ ...config, headers: retryHeaders });
      }
      throw err;
    }
  }
}
