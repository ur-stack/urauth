import type { H3Event } from "h3";
import { getCookie } from "h3";

/** Extract token from a cookie. */
export function extractTokenFromCookie(
  event: H3Event,
  cookieName: string = "access_token",
): string | null {
  return getCookie(event, cookieName) ?? null;
}
