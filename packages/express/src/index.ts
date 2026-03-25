// ── Adapter ──────────────────────────────────────────────────────
export { expressAuth } from "./adapter";

// ── Middleware ────────────────────────────────────────────────────
export { createMiddleware, type MiddlewareOptions } from "./middleware";

// ── Guards ───────────────────────────────────────────────────────
export { guard, protect } from "./guard";

// ── Routes ───────────────────────────────────────────────────────
export { router } from "./router";

// ── Error Handler ────────────────────────────────────────────────
export { errorHandler } from "./error-handler";

// ── Transport ────────────────────────────────────────────────────
export { extractToken } from "./transport/bearer";
export { extractTokenFromCookie } from "./transport/cookie";
export { extractTokenHybrid } from "./transport/hybrid";

// ── Types ────────────────────────────────────────────────────────
export {} from "./types";
