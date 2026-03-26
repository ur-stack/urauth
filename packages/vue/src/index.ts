/**
 * @urauth/vue — Vue composables for urAuth access control.
 *
 * VueUse-inspired reactive composables for permission checking,
 * role management, and auth state in Vue 3 applications.
 */

import { inject, provide, computed, type InjectionKey, type ComputedRef } from "vue";
import type { AuthContext } from "@urauth/ts";
import { canAccess, type PermissionChecker } from "@urauth/ts";
import type { Requirement } from "@urauth/ts";

interface AccessContext {
  ctx: AuthContext;
  checker?: PermissionChecker;
}

const accessKey: InjectionKey<AccessContext> = Symbol("urAuth-access");

/**
 * Provide access control context to descendant components.
 *
 * Call in a parent component's setup:
 *   provideAccess({ ctx: authContext })
 */
export function provideAccess(access: AccessContext): void {
  provide(accessKey, access);
}

// ---------------------------------------------------------------------------
// Internal helper — resolves injected context or throws
// ---------------------------------------------------------------------------

function resolveAccess(): AccessContext {
  const access = inject(accessKey);
  if (!access) {
    throw new Error("urAuth composables require provideAccess() in a parent component.");
  }
  return access;
}

// ---------------------------------------------------------------------------
// useAccess — general-purpose permission check function
// ---------------------------------------------------------------------------

/**
 * Composable for checking permissions in components.
 *
 * Usage:
 *   const { can } = useAccess()
 *   if (can("post", "update")) { ... }
 */
export function useAccess(): { can: (resource: string, action: string, options?: { scope?: string }) => boolean } {
  const resolved = resolveAccess();

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

// ---------------------------------------------------------------------------
// usePermission — reactive computed for a specific permission
// ---------------------------------------------------------------------------

/**
 * Reactive permission check. Returns a computed boolean ref.
 *
 * Usage:
 *   const canEdit = usePermission("post", "update")
 *   <button v-if="canEdit">Edit</button>
 */
export function usePermission(
  resource: string,
  action: string,
  options?: { scope?: string },
): ComputedRef<boolean> {
  const resolved = resolveAccess();
  return computed(() =>
    canAccess(resolved.ctx, resource, action, {
      ...options,
      checker: resolved.checker,
    }),
  );
}

// ---------------------------------------------------------------------------
// useRole — reactive role check
// ---------------------------------------------------------------------------

/**
 * Reactive role check. Returns a computed boolean ref.
 *
 * Usage:
 *   const isAdmin = useRole("admin")
 *   <AdminPanel v-if="isAdmin" />
 */
export function useRole(role: string): ComputedRef<boolean> {
  const resolved = resolveAccess();
  return computed(() => resolved.ctx.hasRole(role));
}

// ---------------------------------------------------------------------------
// useAnyRole — reactive check for any of the given roles
// ---------------------------------------------------------------------------

/**
 * Reactive check for whether the user holds any of the given roles.
 *
 * Usage:
 *   const canModerate = useAnyRole("admin", "moderator")
 */
export function useAnyRole(...roles: string[]): ComputedRef<boolean> {
  const resolved = resolveAccess();
  return computed(() => resolved.ctx.hasAnyRole(...roles));
}

// ---------------------------------------------------------------------------
// useAuthState — reactive auth introspection
// ---------------------------------------------------------------------------

/**
 * Reactive auth state composable. Exposes computed refs for auth status,
 * user, roles, and permissions.
 *
 * Usage:
 *   const { isAuthenticated, user, roles, permissions } = useAuthState()
 *   <LoginButton v-if="!isAuthenticated" />
 */
export function useAuthState(): {
  isAuthenticated: ComputedRef<boolean>;
  user: ComputedRef<unknown>;
  roles: ComputedRef<string[]>;
  permissions: ComputedRef<string[]>;
  tenantId: ComputedRef<string | undefined>;
} {
  const resolved = resolveAccess();
  return {
    isAuthenticated: computed(() => resolved.ctx.isAuthenticated()),
    user: computed(() => resolved.ctx.user),
    roles: computed(() => resolved.ctx.roles.map((r) => r.name)),
    permissions: computed(() => resolved.ctx.permissions.map((p) => p.toString())),
    tenantId: computed(() => resolved.ctx.tenantId),
  };
}

// ---------------------------------------------------------------------------
// useRequirement — reactive composite requirement evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a composite requirement (AllOf / AnyOf) reactively.
 *
 * Usage:
 *   const req = allOf(new Permission("post:update"), new Role("editor"))
 *   const allowed = useRequirement(req)
 */
export function useRequirement(requirement: Requirement): ComputedRef<boolean> {
  const resolved = resolveAccess();
  return computed(() => resolved.ctx.satisfies(requirement));
}

// ---------------------------------------------------------------------------
// useTenant — reactive tenant context
// ---------------------------------------------------------------------------

/**
 * Reactive tenant composable.
 *
 * Usage:
 *   const { tenantId, inTenant, atLevel } = useTenant()
 *   if (inTenant("org-123")) { ... }
 */
export function useTenant(): {
  tenantId: ComputedRef<string | undefined>;
  inTenant: (tenantId: string) => boolean;
  atLevel: (level: string) => string | undefined;
} {
  const resolved = resolveAccess();
  return {
    tenantId: computed(() => resolved.ctx.tenantId),
    inTenant: (tenantId: string) => resolved.ctx.inTenant(tenantId),
    atLevel: (level: string) => resolved.ctx.atLevel(level),
  };
}
