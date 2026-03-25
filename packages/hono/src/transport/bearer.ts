import type { Context } from "hono";
import { extractBearerToken } from "@urauth/node";

/** Extract Bearer token from Authorization header. */
export function extractToken(c: Context): string | null {
  return extractBearerToken(c.req.header("Authorization"));
}
