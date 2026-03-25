/**
 * H3 middleware for urauth — context resolution.
 */

import type { EventHandler } from "h3";
import type { Auth } from "@urauth/node";
import { AuthContext } from "@urauth/ts";
import { extractToken } from "./transport/bearer";
import { extractTokenFromCookie } from "./transport/cookie";
import { extractTokenHybrid } from "./transport/hybrid";
import "./types";

export interface OnRequestOptions {
  /** Allow unauthenticated access. Default: false. */
  optional?: boolean;
  /** Token transport: "bearer" (default), "cookie", or "hybrid". */
  transport?: "bearer" | "cookie" | "hybrid";
  /** Cookie name. Default: "access_token". */
  cookieName?: string;
}

/**
 * Create an onRequest handler that resolves auth context.
 *
 * @example
 * ```ts
 * export default defineEventHandler({
 *   onRequest: [onRequest()],
 *   handler: (event) => event.context.auth.user,
 * });
 * ```
 */
export function createOnRequest(
  auth: Auth,
  options: OnRequestOptions = {},
): EventHandler {
  const { optional = false, transport = "bearer", cookieName = "access_token" } = options;

  return async (event) => {
    let rawToken: string | null;

    switch (transport) {
      case "cookie":
        rawToken = extractTokenFromCookie(event, cookieName);
        break;
      case "hybrid":
        rawToken = extractTokenHybrid(event, cookieName);
        break;
      default:
        rawToken = extractToken(event);
    }

    try {
      event.context.auth = await auth.buildContext(rawToken, { optional });
    } catch (err) {
      if (optional) {
        event.context.auth = AuthContext.anonymous();
      } else {
        throw err;
      }
    }
  };
}
