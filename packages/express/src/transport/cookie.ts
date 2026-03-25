import type { Request } from "express";

/** Extract token from a cookie. */
export function extractTokenFromCookie(
  req: Request,
  cookieName: string = "access_token",
): string | null {
  return (req.cookies as Record<string, string> | undefined)?.[cookieName] ?? null;
}
