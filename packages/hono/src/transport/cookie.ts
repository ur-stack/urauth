import type { Context } from "hono";
import { getCookie } from "hono/cookie";

/** Extract token from a cookie. */
export function extractTokenFromCookie(
  c: Context,
  cookieName: string = "access_token",
): string | null {
  return getCookie(c, cookieName) ?? null;
}
