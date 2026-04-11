/**
 * @urauth/nuxt — Nuxt module for urauth identity management.
 *
 * Implements the BFF (Backend-for-Frontend) pattern: JWTs are stored
 * exclusively in a sealed server-side cookie and never reach the browser.
 * The browser only sees a public session projection (user id, roles, permissions)
 * via the `useAuth()` composable and the `/api/_auth/session` route.
 *
 * Configure via the `urAuth` key in nuxt.config.ts:
 *
 *   export default defineNuxtConfig({
 *     modules: ['@urauth/nuxt'],
 *     urAuth: {
 *       baseURL: 'http://localhost:8000',
 *       authPrefix: '/api/v1/auth',
 *     },
 *   })
 *
 * Set NUXT_SESSION_PASSWORD (≥32 chars) in your environment to seal the session
 * cookie. A random password is auto-generated and saved to .env in dev mode.
 */
import {
  defineNuxtModule,
  addPlugin,
  addImports,
  addServerImportsDir,
  addServerHandler,
  createResolver,
} from "@nuxt/kit";
import { defu } from "defu";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, appendFileSync } from "node:fs";
import { resolve } from "node:path";

export interface ModuleOptions {
  /** Base URL of the urauth backend, e.g. "http://localhost:8000". */
  baseURL: string;
  /** Auth route prefix on the backend (default: "/api/v1/auth"). */
  authPrefix?: string;
  /** Control which auto-registered routes are enabled. */
  routes?: {
    /** Set to false to disable the /api/_auth/register route (default: true). */
    register?: boolean;
  };
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: "@urauth/nuxt",
    configKey: "urAuth",
    compatibility: { nuxt: ">=3.0.0" },
  },
  defaults: {
    baseURL: "",
    authPrefix: "/api/v1/auth",
    routes: { register: true },
  },
  setup(options, nuxt) {
    const resolver = createResolver(import.meta.url);

    // ── 1. Public runtime config (non-secret, available client+server) ──────
    nuxt.options.runtimeConfig.public.urAuth = defu(
      nuxt.options.runtimeConfig.public.urAuth as Record<string, unknown>,
      {
        baseURL: options.baseURL,
        authPrefix: options.authPrefix ?? "/api/v1/auth",
      },
    );

    // ── 2. Server-only session config ────────────────────────────────────────
    // Matches the nuxt-auth-utils convention so projects can use either module.
    // Override at runtime via NUXT_SESSION_PASSWORD, NUXT_SESSION_NAME, etc.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rc = nuxt.options.runtimeConfig as any;
    rc.session = defu(rc.session ?? {}, {
      name: "urauth-session",
      password: process.env.NUXT_SESSION_PASSWORD ?? "",
      maxAge: 60 * 60 * 24 * 7, // 7 days
      cookie: {
        sameSite: "lax" as const,
        secure: !nuxt.options.dev,
        httpOnly: true,
      },
    });

    // ── 3. Dev-mode auto-generate a session password ─────────────────────────
    const sessionCfg = rc.session as Record<string, unknown>;
    if (nuxt.options.dev && !sessionCfg.password) {
      const password = randomBytes(32).toString("base64"); // 44 chars — well above the 32-char minimum
      sessionCfg.password = password;

      const envPath = resolve(nuxt.options.rootDir, ".env");
      const line = `\nNUXT_SESSION_PASSWORD=${password}`;
      if (existsSync(envPath)) {
        const contents = readFileSync(envPath, "utf-8");
        if (!contents.includes("NUXT_SESSION_PASSWORD")) {
          appendFileSync(envPath, line);
        }
      } else {
        appendFileSync(envPath, line);
      }
      console.warn(
        "[urauth] No NUXT_SESSION_PASSWORD found — generated a random one and saved it to .env. " +
        "Set NUXT_SESSION_PASSWORD in production!",
      );
    }

    // ── 4. Virtual type module alias (#urauth-utils) ─────────────────────────
    nuxt.options.alias["#urauth-utils"] = resolver.resolve(
      "../src/runtime/types",
    );

    // ── 5. Plugins (server seeds state; client fetches if SSR was skipped) ───
    addPlugin({
      src: resolver.resolve("../src/runtime/plugins/session.server"),
      mode: "server",
    });
    addPlugin({
      src: resolver.resolve("../src/runtime/plugins/session.client"),
      mode: "client",
    });

    // ── 6. Client-side composable auto-import ────────────────────────────────
    addImports({
      name: "useAuth",
      from: resolver.resolve("../src/runtime/composables/useAuth"),
    });

    // ── 7. Server utility auto-imports (available in app's server/ routes) ───
    addServerImportsDir(resolver.resolve("../src/runtime/server/utils"));

    // ── 8. Auto-registered /api/_auth/* route handlers ───────────────────────
    const routeBase = "../src/runtime/server/api/_auth";

    addServerHandler({
      route: "/api/_auth/session",
      method: "get",
      handler: resolver.resolve(`${routeBase}/session.get`),
    });
    addServerHandler({
      route: "/api/_auth/session",
      method: "delete",
      handler: resolver.resolve(`${routeBase}/session.delete`),
    });
    addServerHandler({
      route: "/api/_auth/login",
      method: "post",
      handler: resolver.resolve(`${routeBase}/login.post`),
    });
    addServerHandler({
      route: "/api/_auth/logout",
      method: "post",
      handler: resolver.resolve(`${routeBase}/logout.post`),
    });
    addServerHandler({
      route: "/api/_auth/refresh",
      method: "post",
      handler: resolver.resolve(`${routeBase}/refresh.post`),
    });

    if (options.routes?.register !== false) {
      addServerHandler({
        route: "/api/_auth/register",
        method: "post",
        handler: resolver.resolve(`${routeBase}/register.post`),
      });
    }
  },
});
