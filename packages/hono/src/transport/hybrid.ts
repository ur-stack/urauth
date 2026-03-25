import type { Context } from "hono";
import { extractToken as extractBearer } from "./bearer";
import { extractTokenFromCookie } from "./cookie";

/** Try Bearer header first, then fall back to cookie. */
export function extractTokenHybrid(
  c: Context,
  cookieName: string = "access_token",
): string | null {
  return extractBearer(c) ?? extractTokenFromCookie(c, cookieName);
}
