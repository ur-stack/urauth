import type { FastifyRequest } from "fastify";
import { extractToken as extractBearer } from "./bearer";
import { extractTokenFromCookie } from "./cookie";

/** Try Bearer header first, then fall back to cookie. */
export function extractTokenHybrid(
  req: FastifyRequest,
  cookieName = "access_token",
): string | null {
  return extractBearer(req) ?? extractTokenFromCookie(req, cookieName);
}
