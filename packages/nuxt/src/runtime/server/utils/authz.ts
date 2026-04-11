// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Nitro auto-imports: createError (h3).
import { requireUserSession } from './session'
import { matchPermission } from '@urauth/ts'

/**
 * Returns true if the session has any permission matching `resource:action`.
 * Supports wildcard permissions ("*", "resource:*").
 */
export function hasPermission(session, resource, action) {
  return (session.permissions ?? []).some(p =>
    matchPermission(p, `${resource}:${action}`),
  )
}

/**
 * Returns true if the session includes the given role.
 */
export function hasRole(session, role) {
  return (session.roles ?? []).includes(role)
}

/**
 * Asserts that the current session is authenticated AND has the given permission.
 * Throws 401 if not logged in, 403 if logged in but permission is missing.
 */
export async function requireUserPermission(event, resource, action) {
  const session = await requireUserSession(event)
  if (!hasPermission(session, resource, action)) {
    throw createError({ statusCode: 403, message: 'Forbidden' })
  }
  return session
}
