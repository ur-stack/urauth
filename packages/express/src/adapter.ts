/**
 * expressAuth() — factory that creates all Express auth utilities.
 *
 * @example
 * ```ts
 * const auth = new Auth({ ... });
 * const { middleware, guard, protect, router } = expressAuth(auth);
 * app.use(middleware());
 * app.get("/admin", guard(Role("admin")), handler);
 * app.use("/auth", router());
 * ```
 */

import type { RequestHandler, Router } from "express";
import type { Auth } from "@urauth/node";
import type { Requirement, AuthContext } from "@urauth/ts";
import { createMiddleware, type MiddlewareOptions } from "./middleware";
import { guard, protect } from "./guard";
import { router } from "./router";

export interface ExpressAuthResult {
  middleware: (options?: MiddlewareOptions) => RequestHandler;
  guard: typeof guard;
  protect: typeof protect;
  router: (() => Router) & { password: () => Router };
}

export function expressAuth(auth: Auth): ExpressAuthResult {
  return {
    middleware: (options?: MiddlewareOptions) => createMiddleware(auth, options),
    guard,
    protect,
    router: Object.assign(
      () => router(auth),
      { password: () => router.password(auth) },
    ),
  };
}
