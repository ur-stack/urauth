import type { Request } from "express";
import { extractBearerToken } from "@urauth/node";

/** Extract Bearer token from Authorization header. */
export function extractToken(req: Request): string | null {
  return extractBearerToken(req.headers.authorization);
}
