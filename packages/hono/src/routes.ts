/**
 * Auto-generated auth routes for Hono.
 *
 * Generates login, refresh, logout endpoints from pipeline config.
 */

import { Hono } from "hono";
import type { Auth } from "@urauth/node";
import { AuthError } from "@urauth/ts";
import type { UrAuthEnv } from "./types";

/**
 * Create a Hono router with auth endpoints.
 *
 * @example
 * ```ts
 * app.route("/auth", authRoutes(auth));
 * // POST /auth/login
 * // POST /auth/refresh
 * // POST /auth/logout
 * // POST /auth/logout-all
 * ```
 */
export function authRoutes(auth: Auth): Hono<UrAuthEnv> {
  const router = new Hono<UrAuthEnv>();

  // POST /login — username/password authentication
  router.post("/login", async (c) => {
    const body = await c.req.json<{ username: string; password: string }>();
    const result = await auth.authenticate(body.username, body.password);
    return c.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    });
  });

  // POST /refresh — rotate refresh token
  router.post("/refresh", async (c) => {
    const body = await c.req.json<{ refreshToken: string }>();
    const result = await auth.lifecycle.refresh(body.refreshToken);
    return c.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    });
  });

  // POST /logout — revoke current token
  router.post("/logout", async (c) => {
    const authCtx = c.get("auth");
    if (authCtx.token) {
      // Re-extract raw token to revoke it
      const authHeader = c.req.header("Authorization");
      if (authHeader !== undefined && authHeader.length > 0) {
        const rawToken = authHeader.replace(/^Bearer\s+/i, "");
        await auth.lifecycle.revoke(rawToken);
      }
    }
    return c.json({ ok: true });
  });

  // POST /logout-all — revoke all user tokens
  router.post("/logout-all", async (c) => {
    const authCtx = c.get("auth");
    if (authCtx.token) {
      await auth.lifecycle.revokeAll(authCtx.token.sub);
    }
    return c.json({ ok: true });
  });

  // Error handler for auth routes
  router.onError((err, c) => {
    if (err instanceof AuthError) {
      return c.json({ error: err.detail }, err.statusCode as 401 | 403);
    }
    throw err;
  });

  return router;
}
