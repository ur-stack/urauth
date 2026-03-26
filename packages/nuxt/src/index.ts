/**
 * @urauth/nuxt — Nuxt module for urauth access control.
 *
 * Provides useAccess() composable with SSR-safe state via useState.
 */

import type { AuthContext } from "@urauth/ts";
import { canAccess, type PermissionChecker } from "@urauth/ts";

interface AccessState {
  ctx: AuthContext | null;
  checker?: PermissionChecker;
}

/** Minimal Ref interface matching Vue/Nuxt's Ref<T>. */
interface Ref<T> {
  value: T;
}

/**
 * Nuxt's useState — declared here because it is auto-imported at runtime
 * but unavailable to the type-checker outside of a Nuxt project.
 */
declare function useState<T>(key: string, init: () => T): Ref<T>;

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
export function useAccess(checker?: PermissionChecker): {
  can: (resource: string, action: string, options?: { scope?: string }) => boolean;
  setContext: (ctx: AuthContext) => void;
  state: Ref<AccessState>;
} {
  // Use Nuxt's useState for SSR hydration safety
  const state: Ref<AccessState> = useState<AccessState>("urAuth-access", () => ({
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
    if (state.value.ctx === null) return false;
    return canAccess(state.value.ctx, resource, action, {
      ...options,
      checker: state.value.checker,
    });
  }

  return { can, setContext, state };
}

export default function urAuthModule(): void {
  // Nuxt module hook — registers composable auto-imports
  // Users call useAccess() directly after importing
}
