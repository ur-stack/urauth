// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Nitro auto-imports: $fetch, useRuntimeConfig (nitro/h3).
import { _useStoredSession } from './session'

/**
 * Per-event refresh lock — ensures that even if multiple concurrent fetchBackend
 * calls observe a 401, only one refresh round-trip is made to the upstream.
 */
const refreshLocks = new WeakMap()

/**
 * Proxies a request to the urauth upstream backend, injecting the session's
 * access token as a Bearer header.
 *
 * On 401, transparently refreshes the token (single-flight per H3Event) and
 * retries once. Throws the original error if refresh fails or produces no token.
 *
 * @param event  The current H3Event (from your Nitro route handler).
 * @param path   Path relative to `runtimeConfig.public.urAuth.baseURL`.
 * @param opts   Additional ofetch options (method, body, headers, …).
 */
export async function fetchBackend(event, path, opts = {}) {
  const { baseURL } = useRuntimeConfig(event).public.urAuth
  const stored = await _useStoredSession(event)
  const accessToken = stored.data.secure?.accessToken

  try {
    return await $fetch(path, {
      ...opts,
      baseURL,
      headers: {
        ...opts.headers,
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      },
    })
  } catch (err) {
    const status = err?.status ?? err?.statusCode
    if (status !== 401 || !stored.data.secure?.refreshToken) throw err

    // Single-flight refresh — one promise per event, shared by all concurrent callers.
    if (!refreshLocks.has(event)) {
      const lock = _doRefresh(event).finally(() => refreshLocks.delete(event))
      refreshLocks.set(event, lock)
    }
    const newAccess = await refreshLocks.get(event)
    if (!newAccess) throw err

    return await $fetch(path, {
      ...opts,
      baseURL,
      headers: { ...opts.headers, Authorization: `Bearer ${newAccess}` },
    })
  }
}

/**
 * Explicitly triggers a token refresh against the upstream backend and updates
 * the session. Returns the new access token, or null on failure.
 *
 * Exposed so `/api/_auth/refresh` can call it directly.
 */
export async function refreshSession(event) {
  return _doRefresh(event)
}

/** Internal — performs the upstream refresh call and updates the session. */
async function _doRefresh(event) {
  const config = useRuntimeConfig(event)
  const { baseURL, authPrefix } = config.public.urAuth
  const stored = await _useStoredSession(event)
  const refreshToken = stored.data.secure?.refreshToken
  if (!refreshToken) return null

  try {
    const res = await $fetch(`${authPrefix}/refresh`, {
      baseURL,
      method: 'POST',
      body: { refresh_token: refreshToken },
    })
    const payload = _decodeJWTPayload(res.access_token)
    await stored.update({
      ...stored.data,
      secure: {
        ...stored.data.secure,
        accessToken: res.access_token,
        refreshToken: res.refresh_token,
        accessExpiresAt: payload.exp * 1000,
      },
    })
    return res.access_token
  } catch {
    return null
  }
}

/** Decode JWT payload without verifying signature (server-side, trusted source). */
function _decodeJWTPayload(token) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Invalid JWT format')
  const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf-8'))
}
