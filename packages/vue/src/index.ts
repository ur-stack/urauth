/**
 * @urauth/vue — Vue composables for urauth access control.
 */

import { inject, provide, type InjectionKey } from "vue";
import { AuthContext, canAccess, type PermissionChecker } from "@urauth/ts";

interface AccessContext {
  ctx: AuthContext;
  checker?: PermissionChecker;
}

const accessKey: InjectionKey<AccessContext> = Symbol("urauth-access");

/**
 * Provide access control context to descendant components.
 *
 * Call in a parent component's setup:
 *   provideAccess({ ctx: authContext })
 */
export function provideAccess(access: AccessContext): void {
  provide(accessKey, access);
}

/**
 * Composable for checking permissions in components.
 *
 * Usage:
 *   const { can } = useAccess()
 *   if (can("post", "update")) { ... }
 */
export function useAccess() {
  const access = inject(accessKey);
  if (!access) {
    throw new Error(
      "useAccess() requires provideAccess() in a parent component.",
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
