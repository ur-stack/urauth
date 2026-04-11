/**
 * @urauth/vue — Vue composables for urAuth access control.
 *
 * VueUse-inspired reactive composables for permission checking,
 * role management, and auth state in Vue 3 applications.
 */

import { inject, provide, computed, ref, type InjectionKey, type ComputedRef, type Ref } from "vue";
import type { AuthContext, TokenPair, PermissionChecker, Requirement, UrAuthClient } from "@urauth/ts";
import { canAccess } from "@urauth/ts";

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

// ---------------------------------------------------------------------------
// provideUrAuthClient — connect an UrAuthClient to the Vue context
// ---------------------------------------------------------------------------

const clientKey: InjectionKey<UrAuthClient> = Symbol("urAuth-client");

/**
 * Provide an UrAuthClient and auto-populate the access context from
 * decoded JWT claims. Reactively updates on token changes.
 *
 * Usage:
 *   // In App.vue setup
 *   const client = new UrAuthClient({ baseURL: "http://localhost:8000" });
 *   provideUrAuthClient(client);
 */
export function provideUrAuthClient(
  client: UrAuthClient,
  checker?: PermissionChecker,
): void {
  provide(clientKey, client);

  // Create a reactive context that updates on token changes
  const ctx = ref(client.getContext()) as Ref<AccessContext["ctx"]>;

  // Hook into the client's onTokenChange to update reactively
  const prevCallback = client.onTokenChange;
  client.onTokenChange = (tokens: TokenPair | null) => {
    prevCallback?.(tokens);
    ctx.value = client.getContext();
  };

  // Provide the reactive access context — use a computed so it stays in sync
  provide(accessKey, computed<AccessContext>(() => ({ ctx: ctx.value, checker })).value);
}

/**
 * Inject the UrAuthClient provided by provideUrAuthClient.
 */
export function useUrAuthClient(): UrAuthClient {
  const client = inject(clientKey);
  if (client === undefined) {
    throw new Error("useUrAuthClient() requires provideUrAuthClient() in a parent component.");
  }
  return client;
}

// ── TanStack Query composables (re-exported) ──────────────────

export { useSession, useLogin, useLogout, useLogoutAll, useRefresh } from "./query";
