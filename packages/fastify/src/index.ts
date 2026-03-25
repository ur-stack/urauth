// ── Plugin ────────────────────────────────────────────────────────
export { urAuthPlugin, type UrAuthPluginOptions } from "./plugin";

// ── Guards ───────────────────────────────────────────────────────
export { createGuard, createProtect, createTenantGuard, createPolicyGuard } from "./guard";

// ── Routes ───────────────────────────────────────────────────────
export { urAuthRoutes, type UrAuthRoutesOptions } from "./routes";

// ── Types ────────────────────────────────────────────────────────
export type { RouteAuthConfig } from "./types";

// ── Transport ────────────────────────────────────────────────────
export { extractToken } from "./transport/bearer";
export { extractTokenFromCookie } from "./transport/cookie";
export { extractTokenHybrid } from "./transport/hybrid";
