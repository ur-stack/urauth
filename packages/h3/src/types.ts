import type { AuthContext } from "@urauth/ts";

/** Augment H3 event context with auth. */
declare module "h3" {
  interface H3EventContext {
    auth: AuthContext;
  }
}

export {};
