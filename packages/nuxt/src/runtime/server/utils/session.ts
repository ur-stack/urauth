// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Nitro auto-imports: useSession, useRuntimeConfig, createError (all from h3/nitro).
import { createHooks } from 'hookable'
import { defu } from 'defu'

/**
 * Hookable emitter for session lifecycle events.
 *
 * Usage:
 *   sessionHooks.hook('fetch', async (session, event) => { ... })
 *   sessionHooks.hook('clear', async (session, event) => { ... })
 */
export const sessionHooks = createHooks()

/**
 * Returns the public projection of the current session.
 * The `secure` field (tokens) is stripped before returning.
 */
export async function getUserSession(event) {
  const stored = await _useStoredSession(event)
  const { secure, ...publicView } = stored.data
  return publicView
}

/**
 * Merges `data` into the current session and returns the updated public view.
 * Existing fields win over incoming fields (defu semantics).
 */
export async function setUserSession(event, data) {
  const stored = await _useStoredSession(event)
  await stored.update(defu(data, stored.data))
  await sessionHooks.callHook('fetch', stored.data, event)
  return getUserSession(event)
}

/**
 * Like getUserSession, but throws 401 if the session has no authenticated user.
 */
export async function requireUserSession(event) {
  const session = await getUserSession(event)
  if (!session.user) {
    throw createError({ statusCode: 401, message: 'Unauthorized' })
  }
  return session
}

/**
 * Fires the `clear` hook, then clears the session cookie entirely.
 */
export async function clearUserSession(event) {
  const stored = await _useStoredSession(event)
  await sessionHooks.callHook('clear', stored.data, event)
  await stored.clear()
  return true
}

/**
 * Internal — returns the raw h3 session object (includes `secure` tokens).
 * Exported so sibling utilities (fetch-backend, api routes) can access it.
 * Server-only; never call from client-side code.
 */
export async function _useStoredSession(event) {
  const { session: cfg } = useRuntimeConfig(event)
  return useSession(event, {
    password: cfg.password,
    name: cfg.name,
    maxAge: cfg.maxAge,
    cookie: cfg.cookie,
  })
}
