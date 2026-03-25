import type { FastifyRequest } from "fastify";
import { extractBearerToken } from "@urauth/node";

/** Extract Bearer token from Authorization header. */
export function extractToken(req: FastifyRequest): string | null {
  return extractBearerToken(req.headers.authorization);
}
