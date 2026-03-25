// ── Plugin ────────────────────────────────────────────────────────
export {
  defineUrAuth,
  createUrAuthNitroPlugin,
  type DefineUrAuthResult,
  type NitroPluginOptions,
} from "./plugin";

// ── Middleware ────────────────────────────────────────────────────
export { createOnRequest, type OnRequestOptions } from "./middleware";

// ── Guards ───────────────────────────────────────────────────────
export {
  requireAuth,
  requirePermission,
  requireRole,
  requireGuard,
  requireTenant,
  requirePolicy,
} from "./guards";

// ── Routes ───────────────────────────────────────────────────────
export { authRoutes } from "./routes";

// ── Transport ────────────────────────────────────────────────────
export { extractToken } from "./transport/bearer";
export { extractTokenFromCookie } from "./transport/cookie";
export { extractTokenHybrid } from "./transport/hybrid";

// ── Types ────────────────────────────────────────────────────────
export {} from "./types";
