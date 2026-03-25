/**
 * Transport — token extraction/injection interface.
 *
 * Framework adapters implement this for their request/response types.
 * These are the framework-agnostic base types.
 */

/** Generic token transport interface. Framework adapters implement per-framework. */
export interface Transport<TRequest = unknown, TResponse = unknown> {
  extractToken(request: TRequest): string | null;
  setToken(response: TResponse, token: string): void;
  deleteToken(response: TResponse): void;
}

/** Extract a Bearer token from an Authorization header value. */
export function extractBearerToken(authHeader: string | null | undefined): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0]!.toLowerCase() !== "bearer") return null;
  return parts[1]!;
}
