/**
 * @urauth/react — React hooks for urauth access control.
 */

import { createContext, useContext } from "react";
import type { AuthContext } from "@urauth/ts";
import { canAccess, type PermissionChecker } from "@urauth/ts";

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
  if (!access) {
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
