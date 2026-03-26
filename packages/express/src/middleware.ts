/**
 * Express middleware for urauth — context resolution and token extraction.
 */

import type { RequestHandler } from "express";
import type { Auth } from "@urauth/node";
import { extractToken } from "./transport/bearer";
import { extractTokenFromCookie } from "./transport/cookie";
import { extractTokenHybrid } from "./transport/hybrid";
import "./types";

export interface MiddlewareOptions {
  /** Allow unauthenticated access (sets anonymous context). Default: false. */
  optional?: boolean;
  /** Token transport: "bearer" (default), "cookie", or "hybrid". */
  transport?: "bearer" | "cookie" | "hybrid";
  /** Cookie name when using cookie or hybrid transport. Default: "access_token". */
  cookieName?: string;
}

/**
 * Express middleware that resolves auth context from the request.
 *
 * Sets `req.auth` to an AuthContext instance.
 *
 * @example
 * ```ts
 * app.use(middleware());
 * app.get("/me", (req, res) => res.json(req.auth.user));
 * ```
 */
export function createMiddleware(auth: Auth, options: MiddlewareOptions = {}): RequestHandler {
  const { optional = false, transport = "bearer", cookieName = "access_token" } = options;

  return async (req, res, next) => {
    try {
      let rawToken: string | null;

      switch (transport) {
        case "bearer":
          rawToken = extractToken(req);
          break;
        case "cookie":
          rawToken = extractTokenFromCookie(req, cookieName);
          break;
        case "hybrid":
          rawToken = extractTokenHybrid(req, cookieName);
          break;
      }

      req.auth = await auth.buildContext(rawToken, { optional });
      next();
    } catch (err) {
      next(err);
    }
  };
}
