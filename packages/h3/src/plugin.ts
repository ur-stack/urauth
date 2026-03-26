/**
 * defineUrAuth — factory that creates all H3 auth utilities.
 *
 * Also provides createUrAuthNitroPlugin for Nuxt server integration.
 */

import type { Auth } from "@urauth/node";
import { createOnRequest, type OnRequestOptions } from "./middleware";
import {
  requireAuth,
  requirePermission,
  requireRole,
  requireGuard,
  requireTenant,
  requirePolicy,
} from "./guards";
import { authRoutes } from "./routes";

export interface DefineUrAuthResult {
  onRequest: (options?: OnRequestOptions) => ReturnType<typeof createOnRequest>;
  requireAuth: typeof requireAuth;
  requirePermission: typeof requirePermission;
  requireRole: typeof requireRole;
  requireGuard: typeof requireGuard;
  requireTenant: typeof requireTenant;
  requirePolicy: typeof requirePolicy;
  authRoutes: () => ReturnType<typeof authRoutes>;
}

/**
 * Create all H3 auth utilities from an Auth instance.
 *
 * @example
 * ```ts
 * const auth = new Auth({ ... });
 * const { onRequest, requireAuth, requirePermission, authRoutes } = defineUrAuth(auth);
 * ```
 */
export function defineUrAuth(auth: Auth): DefineUrAuthResult {
  return {
    onRequest: (options?: OnRequestOptions) => createOnRequest(auth, options),
    requireAuth,
    requirePermission,
    requireRole,
    requireGuard,
    requireTenant,
    requirePolicy,
    authRoutes: () => authRoutes(auth),
  };
}

export interface NitroPluginOptions {
  auth: Auth;
  routes?: { prefix?: string };
  exclude?: string[];
  transport?: "bearer" | "cookie" | "hybrid";
  cookieName?: string;
}

/**
 * Create a Nitro plugin for Nuxt server integration.
 *
 * @example
 * ```ts
 * // ~/server/plugins/auth.ts
 * export default createUrAuthNitroPlugin({ auth, routes: { prefix: "/api/auth" } });
 * ```
 */
export function createUrAuthNitroPlugin(opts: NitroPluginOptions): { onRequest: ReturnType<typeof createOnRequest>; auth: Auth; routes: ReturnType<typeof authRoutes> | undefined } {
  const { auth, transport, cookieName } = opts;
  const onRequest = createOnRequest(auth, {
    optional: true,
    transport,
    cookieName,
  });

  return {
    onRequest,
    auth,
    routes: opts.routes ? authRoutes(auth) : undefined,
  };
}
