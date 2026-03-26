import type { AuthContext } from "@urauth/ts";

/** Augment Express Request with auth property. */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth: AuthContext;
    }
  }
}

export {};
