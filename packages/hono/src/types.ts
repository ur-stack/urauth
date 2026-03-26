import type { AuthContext } from "@urauth/ts";

/** Hono environment type with urauth auth context. */
export interface UrAuthEnv {
  Variables: {
    auth: AuthContext;
  };
}
