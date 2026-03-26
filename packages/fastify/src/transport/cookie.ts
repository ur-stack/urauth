import type { FastifyRequest } from "fastify";

/** Extract token from a cookie (requires @fastify/cookie). */
export function extractTokenFromCookie(
  req: FastifyRequest,
  cookieName = "access_token",
): string | null {
  const cookies = (req as unknown as { cookies?: Record<string, string> }).cookies;
  return cookies?.[cookieName] ?? null;
}
