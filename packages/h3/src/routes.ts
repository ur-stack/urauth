/**
 * Auto-generated auth routes for H3.
 */

import { createRouter, defineEventHandler, readBody, getHeader } from "h3";
import type { Router } from "h3";
import type { Auth } from "@urauth/node";
import "./types";

/**
 * Create an H3 router with auth endpoints.
 *
 * @example
 * ```ts
 * const router = authRoutes(auth);
 * app.use("/auth", router.handler);
 * ```
 */
export function authRoutes(auth: Auth): Router {
  const router = createRouter();

  // POST /login
  router.post("/login", defineEventHandler(async (event) => {
    const body = await readBody<{ username: string; password: string }>(event);
    const result = await auth.authenticate(body.username, body.password);
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    };
  }));

  // POST /refresh
  router.post("/refresh", defineEventHandler(async (event) => {
    const body = await readBody<{ refreshToken: string }>(event);
    const result = await auth.lifecycle.refresh(body.refreshToken);
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    };
  }));

  // POST /logout
  router.post("/logout", defineEventHandler(async (event) => {
    if (event.context.auth.token) {
      const authHeader = getHeader(event, "Authorization");
      if (authHeader !== undefined && authHeader.length > 0) {
        const rawToken = authHeader.replace(/^Bearer\s+/i, "");
        await auth.lifecycle.revoke(rawToken);
      }
    }
    return { ok: true };
  }));

  // POST /logout-all
  router.post("/logout-all", defineEventHandler(async (event) => {
    if (event.context.auth.token) {
      await auth.lifecycle.revokeAll(event.context.auth.token.sub);
    }
    return { ok: true };
  }));

  return router;
}
