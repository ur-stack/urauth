/**
 * @urauth/nuxt runtime types — aliased as '#urauth-utils'.
 *
 * Extend the empty interfaces via declaration merging in your project:
 *
 *   declare module '#urauth-utils' {
 *     interface User { username: string }
 *     interface SecureSessionData { idToken?: string }
 *   }
 */

/** User-extensible public user fields. */
export interface User {}

/** User-extensible public session fields (client-visible, not tokens). */
export interface UserSession {}

/** User-extensible server-only secure fields stored in the sealed cookie. */
export interface SecureSessionData {}

/** Public projection of the session — safe to send to the browser. */
export interface PublicSession {
  user?: { id: string } & User
  roles: string[]
  permissions: string[]
  loggedInAt: number
}

/**
 * Full session stored inside the sealed httpOnly server-side cookie.
 * The `secure` field is stripped at the `/api/_auth/session` boundary
 * and never reaches the browser.
 */
export interface StoredSession extends PublicSession {
  secure?: {
    accessToken: string
    refreshToken: string
    /** Unix epoch milliseconds — from the JWT `exp` claim × 1000. */
    accessExpiresAt: number
  } & SecureSessionData
}
