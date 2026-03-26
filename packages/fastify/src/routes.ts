/**
 * Auto-generated auth routes for Fastify.
 */

import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import type { Auth } from "@urauth/node";
import "./types";

export interface UrAuthRoutesOptions {
  auth: Auth;
  prefix?: string;
}

const routesPlugin: FastifyPluginAsync<UrAuthRoutesOptions> = (app, opts): Promise<void> => {
  const { auth } = opts;

  // POST /login
  app.post("/login", async (request) => {
    const { username, password } = request.body as { username: string; password: string };
    const result = await auth.authenticate(username, password);
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    };
  });

  // POST /refresh
  app.post("/refresh", async (request) => {
    const { refreshToken } = request.body as { refreshToken: string };
    const result = await auth.lifecycle.refresh(refreshToken);
    return {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      tokenType: result.tokenType,
    };
  });

  // POST /logout
  app.post("/logout", async (request) => {
    if (request.auth.token) {
      const authHeader = request.headers.authorization;
      if (authHeader !== undefined && authHeader.length > 0) {
        const rawToken = authHeader.replace(/^Bearer\s+/i, "");
        await auth.lifecycle.revoke(rawToken);
      }
    }
    return { ok: true };
  });

  // POST /logout-all
  app.post("/logout-all", async (request) => {
    if (request.auth.token) {
      await auth.lifecycle.revokeAll(request.auth.token.sub);
    }
    return { ok: true };
  });

  return Promise.resolve();
};

export const urAuthRoutes = fp(routesPlugin, {
  name: "@urauth/fastify/routes",
  fastify: ">=4.0.0",
});
