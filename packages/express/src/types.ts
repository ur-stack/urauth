import type { AuthContext } from "@urauth/ts";

/** Augment Express Request with auth property. */
declare global {
  namespace Express {
    interface Request {
      auth: AuthContext;
    }
  }
}

export {};
