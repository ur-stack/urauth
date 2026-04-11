/**
 * Endpoint registry — define, customize, and generate query keys/functions
 * from backend route definitions.
 */

import type { UrAuthClient } from "./client.js";
import type { HttpResponse } from "./http.js";

export interface EndpointDef<TData = unknown, TResponse = unknown> {
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  path: string;
  /** Override the generated query key name (defaults to the registry key). */
  name?: string;
  /** Transform the response before returning. */
  transform?: (response: HttpResponse<TResponse>) => TData;
}

export interface EndpointRegistry {
  endpoints: Record<string, EndpointDef>;
}

/** Default auth endpoints matching the urauth FastAPI router. */
export const defaultAuthEndpoints: EndpointRegistry = {
  endpoints: {
    login: { method: "POST", path: "/login" },
    refresh: { method: "POST", path: "/refresh" },
    logout: { method: "POST", path: "/logout" },
    logoutAll: { method: "POST", path: "/logout-all" },
  },
};

/**
 * Merge custom endpoint definitions with a base registry.
 *
 * ```ts
 * const endpoints = defineEndpoints({
 *   login: { method: "POST", path: "/login", name: "signIn" },
 *   register: { method: "POST", path: "/register" },
 *   me: { method: "GET", path: "/me", name: "currentUser" },
 * });
 * ```
 */
export function defineEndpoints(
  custom: Record<string, EndpointDef>,
  base: EndpointRegistry = defaultAuthEndpoints,
): EndpointRegistry {
  return {
    endpoints: { ...base.endpoints, ...custom },
  };
}

/**
 * Generate query keys from an endpoint registry.
 *
 * Uses the endpoint's `name` if provided, otherwise the registry key.
 *
 * ```ts
 * const keys = createQueryKeys(endpoints);
 * // keys.signIn → ["urauth", "signIn"]
 * ```
 */
export function createQueryKeys(
  registry: EndpointRegistry,
  prefix: readonly string[] = ["urauth"],
): Record<string, readonly string[]> {
  const keys: Record<string, readonly string[]> = {};

  for (const [key, def] of Object.entries(registry.endpoints)) {
    const name = def.name ?? key;
    keys[name] = [...prefix, name] as const;
  }

  return keys;
}

/**
 * Generate callable functions from an endpoint registry.
 *
 * Each function calls `client.request()` with the auth header injected
 * and auto-refresh on 401.
 *
 * ```ts
 * const fns = createEndpointFunctions(client, endpoints);
 * await fns.signIn({ username: "admin", password: "secret" });
 * const user = await fns.currentUser();
 * ```
 */
export function createEndpointFunctions(
  client: UrAuthClient,
  registry: EndpointRegistry,
  authPrefix = "/auth",
): Record<string, (data?: unknown) => Promise<unknown>> {
  const fns: Record<string, (data?: unknown) => Promise<unknown>> = {};

  for (const [key, def] of Object.entries(registry.endpoints)) {
    const name = def.name ?? key;
    const url = `${authPrefix}${def.path}`;

    fns[name] = async (data?: unknown) => {
      const config =
        def.method === "GET"
          ? { method: "GET" as const, url, params: data as Record<string, string> | undefined }
          : { method: def.method, url, data };

      const response = await client.request(config);
      return def.transform ? def.transform(response) : response.data;
    };
  }

  return fns;
}
