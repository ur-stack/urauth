/**
 * @urauth/react — React hooks for urauth access control.
 */

import { createContext, useContext, useState, useEffect, createElement } from "react";
import type { ReactNode } from "react";
import type { AuthContext, TokenPair, PermissionChecker, UrAuthClient } from "@urauth/ts";
import { canAccess } from "@urauth/ts";

interface AccessContext {
  ctx: AuthContext;
  checker?: PermissionChecker;
}

const UrAuthContext = createContext<AccessContext | null>(null);

/**
 * Provider component props.
 *
 * Usage:
 *   <UrAuthProvider value={{ ctx: authContext }}>
 *     <App />
 *   </UrAuthProvider>
 */
export const UrAuthProvider = UrAuthContext.Provider;

/**
 * Hook for checking permissions in components.
 *
 * Usage:
 *   const { can } = useAccess()
 *   if (can("post", "update")) { ... }
 */
export function useAccess(): { can: (resource: string, action: string, options?: { scope?: string }) => boolean } {
  const access = useContext(UrAuthContext);
  if (access === null) {
    throw new Error(
      "useAccess() requires <UrAuthProvider> in a parent component.",
    );
  }

  const resolved = access;

  function can(
    resource: string,
    action: string,
    options?: { scope?: string },
  ): boolean {
    return canAccess(resolved.ctx, resource, action, {
      ...options,
      checker: resolved.checker,
    });
  }

  return { can };
}

// ── Client-aware provider ─────────────────────────────────────

/**
 * Provider that connects an UrAuthClient to the React context.
 *
 * Automatically decodes the JWT and provides the AuthContext to all
 * descendant components. Re-renders on token changes (login/refresh/logout).
 *
 * Usage:
 *   const client = new UrAuthClient({ baseURL: "http://localhost:8000" });
 *   <UrAuthClientProvider client={client}>
 *     <App />
 *   </UrAuthClientProvider>
 */
export function UrAuthClientProvider({
  client,
  checker,
  children,
}: {
  client: UrAuthClient;
  checker?: PermissionChecker;
  children: ReactNode;
}): ReturnType<typeof createElement> {
  const [ctx, setCtx] = useState<AuthContext>(() => client.getContext());

  useEffect(() => {
    const prevCallback = client.onTokenChange;

    client.onTokenChange = (tokens: TokenPair | null) => {
      prevCallback?.(tokens);
      setCtx(client.getContext());
    };

    // Sync initial state
    setCtx(client.getContext());

    return () => {
      client.onTokenChange = prevCallback;
    };
  }, [client]);

  return createElement(UrAuthContext.Provider, { value: { ctx, checker } }, children);
}

// ── TanStack Query hooks (re-exported) ────────────────────────

export { useSession, useLogin, useLogout, useLogoutAll, useRefresh } from "./query";
