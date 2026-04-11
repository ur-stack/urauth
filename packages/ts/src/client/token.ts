/**
 * Token storage — pluggable persistence for access and refresh tokens.
 */

import type { TokenPayload } from "../types.js";

export interface TokenStorage {
  getAccessToken(): string | null;
  getRefreshToken(): string | null;
  setTokens(accessToken: string, refreshToken: string): void;
  clear(): void;
}

/** In-memory token storage (lost on page reload). */
export function memoryStorage(): TokenStorage {
  let accessToken: string | null = null;
  let refreshToken: string | null = null;

  return {
    getAccessToken: () => accessToken,
    getRefreshToken: () => refreshToken,
    setTokens(access, refresh) {
      accessToken = access;
      refreshToken = refresh;
    },
    clear() {
      accessToken = null;
      refreshToken = null;
    },
  };
}

/** localStorage-backed token storage. */
export function localStorageTokens(prefix = "urauth"): TokenStorage {
  const accessKey = `${prefix}:access_token`;
  const refreshKey = `${prefix}:refresh_token`;

  return {
    getAccessToken: () => localStorage.getItem(accessKey),
    getRefreshToken: () => localStorage.getItem(refreshKey),
    setTokens(access, refresh) {
      localStorage.setItem(accessKey, access);
      localStorage.setItem(refreshKey, refresh);
    },
    clear() {
      localStorage.removeItem(accessKey);
      localStorage.removeItem(refreshKey);
    },
  };
}

/** Decode a JWT payload without verifying the signature (frontend use only). */
export function decodeJWT(token: string): TokenPayload {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const payload = parts[1];
  // Handle base64url: replace URL-safe chars and pad
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  const json = atob(padded);

  return JSON.parse(json) as TokenPayload;
}
