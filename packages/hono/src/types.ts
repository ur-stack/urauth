import type { AuthContext } from "@urauth/ts";

/** Hono environment type with urauth auth context. */
export type UrAuthEnv = {
  Variables: {
    auth: AuthContext;
  };
};
