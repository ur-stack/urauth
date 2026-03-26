/**
 * Auto-generated auth routes for Express.
 */

import { Router, type RequestHandler, type Request, type Response, type NextFunction } from "express";
import type { Auth } from "@urauth/node";
import "./types";

export interface AuthRouterOptions {
  /** Only generate password routes. */
  passwordOnly?: boolean;
  /** Only generate OAuth routes. */
  oauthOnly?: boolean;
}

/**
 * Create an Express router with auth endpoints.
 *
 * @example
 * ```ts
 * app.use("/auth", router());
 * // POST /auth/login
 * // POST /auth/refresh
 * // POST /auth/logout
 * // POST /auth/logout-all
 * ```
 */
function createRouter(auth: Auth): Router {
  const r = Router();
  r.use(((req: Request, res: Response, next: NextFunction) => {
    // Body parsing — Express requires json() middleware
    next();
  }) as RequestHandler);

  addPasswordRoutes(r, auth);
  return r;
}

function addPasswordRoutes(r: Router, auth: Auth): void {
  // POST /login
  r.post("/login", (async (req, res, next) => {
    try {
      const { username, password } = req.body as { username: string; password: string };
      const result = await auth.authenticate(username, password);
      res.json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: result.tokenType,
      });
    } catch (err) {
      next(err);
    }
  }) as RequestHandler);

  // POST /refresh
  r.post("/refresh", (async (req, res, next) => {
    try {
      const { refreshToken } = req.body as { refreshToken: string };
      const result = await auth.lifecycle.refresh(refreshToken);
      res.json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: result.tokenType,
      });
    } catch (err) {
      next(err);
    }
  }) as RequestHandler);

  // POST /logout
  r.post("/logout", (async (req, res, next) => {
    try {
      if (req.auth.token) {
        const authHeader = req.headers.authorization;
        if (authHeader !== undefined && authHeader.length > 0) {
          const rawToken = authHeader.replace(/^Bearer\s+/i, "");
          await auth.lifecycle.revoke(rawToken);
        }
      }
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }) as RequestHandler);

  // POST /logout-all
  r.post("/logout-all", (async (req, res, next) => {
    try {
      if (req.auth.token) {
        await auth.lifecycle.revokeAll(req.auth.token.sub);
      }
      res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  }) as RequestHandler);
}

/** Create sub-routers for specific route groups. */
createRouter.password = (auth: Auth): Router => {
  const r = Router();
  addPasswordRoutes(r, auth);
  return r;
};

export { createRouter as router };
