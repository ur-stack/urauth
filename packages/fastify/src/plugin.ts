/**
 * urAuthPlugin — Fastify plugin that integrates urauth.
 *
 * Decorates the app with `app.auth` helpers and resolves auth context
 * on every request via `onRequest` hook.
 */

import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyRequest,
} from "fastify";
import fp from "fastify-plugin";
import type { Auth } from "@urauth/node";
import { AuthContext, AuthError } from "@urauth/ts";
import { extractToken } from "./transport/bearer";
import { extractTokenFromCookie } from "./transport/cookie";
import { extractTokenHybrid } from "./transport/hybrid";
import { createGuard, createProtect, createTenantGuard, createPolicyGuard } from "./guard";
import "./types";

export interface UrAuthPluginOptions {
  auth: Auth;
  /** Token transport: "bearer" (default), "cookie", or "hybrid". */
  transport?: "bearer" | "cookie" | "hybrid";
  /** Cookie name for cookie/hybrid transport. */
  cookieName?: string;
}

const plugin: FastifyPluginAsync<UrAuthPluginOptions> = async (
  app: FastifyInstance,
  opts: UrAuthPluginOptions,
) => {
  const { auth, transport = "bearer", cookieName = "access_token" } = opts;

  // Decorate request with auth property
  app.decorateRequest("auth", null as unknown as AuthContext);

  // Decorate app with auth helpers
  app.decorate("auth", {
    guard: createGuard,
    protect: createProtect,
    tenant: createTenantGuard,
    policy: createPolicyGuard,
  });

  // Resolve auth context on every request
  app.addHook("onRequest", async (request) => {
    let rawToken: string | null;

    switch (transport) {
      case "cookie":
        rawToken = extractTokenFromCookie(request, cookieName);
        break;
      case "hybrid":
        rawToken = extractTokenHybrid(request, cookieName);
        break;
      default:
        rawToken = extractToken(request);
    }

    // Check route-level auth config
    const routeConfig = request.routeOptions?.config?.auth;
    const optional = routeConfig?.optional ?? !routeConfig?.require;

    try {
      request.auth = await auth.buildContext(rawToken, { optional });
    } catch (err) {
      if (optional) {
        request.auth = AuthContext.anonymous();
      } else {
        throw err;
      }
    }

    // If route has a require config, check it
    if (routeConfig?.require && request.auth.isAuthenticated()) {
      if (!request.auth.satisfies(routeConfig.require)) {
        const { ForbiddenError } = await import("@urauth/ts");
        throw new ForbiddenError("Requirement not satisfied");
      }
    }
  });

  // Error handler for auth errors
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof AuthError) {
      reply.status(error.statusCode).send({ error: error.detail });
      return;
    }
    throw error;
  });
};

export const urAuthPlugin = fp(plugin, {
  name: "@urauth/fastify",
  fastify: ">=4.0.0",
});
