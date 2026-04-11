// @ts-nocheck — runtime file: processed by Nuxt, not tsc.
// Nuxt auto-imports: useState, computed, $fetch.
import { matchPermission } from '@urauth/ts'

const EMPTY_SESSION = () => ({
  user: undefined,
  roles: [],
  permissions: [],
  loggedInAt: 0,
})

/**
 * Reactive composable for urauth identity management.
 *
 * Auto-imported by the @urauth/nuxt module — no explicit import needed.
 *
 * The session is server-seeded on SSR (no visible flash) and kept fresh via
 * `/api/_auth/session`. Tokens are never stored in the browser — they live
 * exclusively in the sealed httpOnly session cookie managed by Nitro.
 *
 * @example
 *   const { isAuthenticated, user, roles, login, logout, can } = useAuth()
 *   await login({ username: 'alice', password: 'secret' })
 *   if (can('task', 'write')) showCreateButton()
 */
export function useAuth() {
  const session = useState('urauth:session', EMPTY_SESSION)
  const ready = useState('urauth:ready', () => false)

  const isAuthenticated = computed(() => !!session.value.user)
  const user = computed(() => session.value.user ?? null)
  const roles = computed(() => session.value.roles ?? [])
  const permissions = computed(() => session.value.permissions ?? [])

  /** Re-fetches the session from the server and updates reactive state. */
  async function fetch() {
    session.value = await $fetch('/api/_auth/session')
    ready.value = true
  }

  /** Clears the local session state without touching the server. */
  async function clear() {
    await $fetch('/api/_auth/session', { method: 'DELETE' })
    session.value = EMPTY_SESSION()
    ready.value = true
  }

  /** Authenticates with the backend and stores the session server-side. */
  async function login(credentials) {
    session.value = await $fetch('/api/_auth/login', {
      method: 'POST',
      body: credentials,
    })
    ready.value = true
  }

  /** Revokes the upstream token and clears the local session. */
  async function logout() {
    await $fetch('/api/_auth/logout', { method: 'POST' })
    session.value = EMPTY_SESSION()
  }

  /**
   * Returns true if the current session has a permission matching
   * `resource:action`. Supports wildcard permissions ("*", "resource:*").
   */
  function can(resource, action) {
    return (session.value.permissions ?? []).some(p =>
      matchPermission(p, `${resource}:${action}`),
    )
  }

  /** Returns true if the current session includes the given role. */
  function hasRole(role) {
    return (session.value.roles ?? []).includes(role)
  }

  return {
    ready,
    isAuthenticated,
    user,
    session,
    roles,
    permissions,
    fetch,
    clear,
    login,
    logout,
    can,
    hasRole,
  }
}
