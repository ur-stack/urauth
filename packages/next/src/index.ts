/**
 * @urauth/next — Next.js utilities for urauth access control.
 *
 * Provides useAccess() hook with client-side state management.
 * For server-side checks, use @urauth/node or @urauth/ts directly.
 */

"use client";

import { createContext, createElement, useContext, useState, useCallback, type ReactNode, type ReactElement } from "react";
import type { AuthContext } from "@urauth/ts";
import { canAccess, type PermissionChecker } from "@urauth/ts";

interface AccessState {
  ctx: AuthContext | null;
  checker?: PermissionChecker;
}

const UrAuthContext = createContext<{
  state: AccessState;
  setContext: (ctx: AuthContext, checker?: PermissionChecker) => void;
} | null>(null);

/**
 * Provider for Next.js client components.
 *
 * Usage:
 *   <UrAuthProvider>
 *     <App />
 *   </UrAuthProvider>
 */
export function UrAuthProvider({ children }: { children: ReactNode }): ReactElement {
  const [state, setState] = useState<AccessState>({ ctx: null });

  const setContext = useCallback((ctx: AuthContext, checker?: PermissionChecker) => {
    setState({ ctx, checker });
  }, []);

  return createElement(UrAuthContext.Provider, { value: { state, setContext } }, children);
}

/**
 * Hook for checking permissions in Next.js client components.
 *
 * Usage:
 *   const { can, setContext } = useAccess()
 *   setContext(authContext)
 *   if (can("post", "update")) showEditButton()
 */
export function useAccess(): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean;
  setContext: (ctx: AuthContext, checker?: PermissionChecker) => void;
} {
  const context = useContext(UrAuthContext);
  if (!context) {
    throw new Error(
      "useAccess() requires <UrAuthProvider> in a parent component.",
    );
  }

  const resolved = context;

  function can(
    resource: string,
    action: string,
    options?: { scope?: string },
  ): boolean {
    if (resolved.state.ctx === null) return false;
    return canAccess(resolved.state.ctx, resource, action, {
      ...options,
      checker: resolved.state.checker,
    });
  }

  return { can, setContext: resolved.setContext };
}
