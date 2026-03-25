import type { H3Event } from "h3";
import { getHeader } from "h3";
import { extractBearerToken } from "@urauth/node";

/** Extract Bearer token from Authorization header. */
export function extractToken(event: H3Event): string | null {
  return extractBearerToken(getHeader(event, "Authorization"));
}
