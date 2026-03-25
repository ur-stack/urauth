import type { AuthContext, Requirement } from "@urauth/ts";
import type {
  FastifyRequest,
  FastifyInstance,
  preHandlerHookHandler,
} from "fastify";

/** Route-level auth config. */
export interface RouteAuthConfig {
  require?: Requirement;
  optional?: boolean;
}

/** Augment Fastify types. */
declare module "fastify" {
  interface FastifyRequest {
    auth: AuthContext;
  }

  interface FastifyInstance {
    auth: {
      guard: (requirement: Requirement) => preHandlerHookHandler;
      protect: () => preHandlerHookHandler;
      tenant: (opts: { level: string }) => preHandlerHookHandler;
      policy: (check: (ctx: AuthContext) => boolean) => preHandlerHookHandler;
    };
  }

  interface FastifyContextConfig {
    auth?: RouteAuthConfig;
  }
}

export type {};
