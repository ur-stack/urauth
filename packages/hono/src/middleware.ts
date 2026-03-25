/**
 * Hono middleware for urauth — context resolution and token extraction.
 */

import type { MiddlewareHandler } from "hono";
import type { Auth } from "@urauth/node";
import { extractToken } from "./transport/bearer";
import { extractTokenFromCookie } from "./transport/cookie";
import { extractTokenHybrid } from "./transport/hybrid";

export interface UrAuthMiddlewareOptions {
  /** Allow unauthenticated access (sets anonymous context). Default: false. */
  optional?: boolean;
  /** Token transport: "bearer" (default), "cookie", or "hybrid". */
  transport?: "bearer" | "cookie" | "hybrid";
  /** Cookie name when using cookie or hybrid transport. Default: "access_token". */
  cookieName?: string;
}

/**
 * Hono middleware that resolves auth context from the request.
 *
 * Sets `c.get("auth")` to an AuthContext instance.
 *
 * @example
 * ```ts
 * app.use("*", urAuthMiddleware(auth));
 * app.get("/me", (c) => c.json(c.get("auth").user));
 * ```
 */
export function urAuthMiddleware(
  auth: Auth,
  options: UrAuthMiddlewareOptions = {},
): MiddlewareHandler {
  const { optional = false, transport = "bearer", cookieName = "access_token" } = options;

  return async (c, next) => {
    let rawToken: string | null;

    switch (transport) {
      case "cookie":
        rawToken = extractTokenFromCookie(c, cookieName);
        break;
      case "hybrid":
        rawToken = extractTokenHybrid(c, cookieName);
        break;
      default:
        rawToken = extractToken(c);
    }

    const ctx = await auth.buildContext(rawToken, { optional });
    c.set("auth", ctx);
    await next();
  };
}
