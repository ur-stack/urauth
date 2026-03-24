/**
 * @urauth/nuxt — Nuxt module for urauth access control.
 *
 * Provides useAccess() composable with SSR-safe state via useState.
 */

import { AuthContext, canAccess, type PermissionChecker } from "@urauth/ts";

interface AccessState {
  ctx: AuthContext | null;
  checker?: PermissionChecker;
}

// Re-export for Nuxt auto-imports
export { canAccess } from "@urauth/ts";

/**
 * SSR-safe composable for access control in Nuxt.
 *
 * Usage in pages/components:
 *   const { can, setContext } = useAccess()
 *   setContext(authContext)
 *   if (can("post", "update")) showEditButton()
 */
export function useAccess(checker?: PermissionChecker) {
  // Use Nuxt's useState for SSR hydration safety
  // @ts-expect-error — useState is auto-imported in Nuxt
  const state = useState<AccessState>("urauth-access", () => ({
    ctx: null,
  }));

  function setContext(ctx: AuthContext): void {
    state.value = { ...state.value, ctx, checker: checker ?? state.value.checker };
  }

  function can(
    resource: string,
    action: string,
    options?: { scope?: string },
  ): boolean {
    if (!state.value.ctx) return false;
    return canAccess(state.value.ctx, resource, action, {
      ...options,
      checker: state.value.checker,
    });
  }

  return { can, setContext, state };
}

export default function urauthModule() {
  // Nuxt module hook — registers composable auto-imports
  // Users call useAccess() directly after importing
}
