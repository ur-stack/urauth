import type { H3Event } from "h3";
import { extractToken as extractBearer } from "./bearer";
import { extractTokenFromCookie } from "./cookie";

/** Try Bearer header first, then fall back to cookie. */
export function extractTokenHybrid(
  event: H3Event,
  cookieName = "access_token",
): string | null {
  return extractBearer(event) ?? extractTokenFromCookie(event, cookieName);
}
