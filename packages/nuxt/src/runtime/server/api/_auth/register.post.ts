// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Nitro auto-imports: defineEventHandler, readBody, useRuntimeConfig, $fetch, createError.
// Module auto-imports: setUserSession (from server/utils/session).
import { decodeJWT } from '@urauth/ts'

export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  if (!body?.username || !body?.password) {
    throw createError({ statusCode: 400, message: 'username and password are required' })
  }

  const { baseURL, authPrefix } = useRuntimeConfig(event).public.urAuth

  // Register the new account on the upstream.
  try {
    await $fetch(`${authPrefix}/register`, {
      baseURL,
      method: 'POST',
      body: { username: body.username, password: body.password },
    })
  } catch (err) {
    throw createError({
      statusCode: err?.status ?? err?.statusCode ?? 400,
      message: err?.data?.detail ?? 'Registration failed',
    })
  }

  // Auto-login immediately after registration.
  let loginRes
  try {
    loginRes = await $fetch(`${authPrefix}/login`, {
      baseURL,
      method: 'POST',
      body: { username: body.username, password: body.password },
    })
  } catch (err) {
    throw createError({
      statusCode: err?.status ?? err?.statusCode ?? 401,
      message: 'Account created but login failed',
    })
  }

  const payload = decodeJWT(loginRes.access_token)

  return setUserSession(event, {
    user: { id: payload.sub },
    roles: payload.roles ?? [],
    permissions: payload.permissions ?? [],
    loggedInAt: Date.now(),
    secure: {
      accessToken: loginRes.access_token,
      refreshToken: loginRes.refresh_token,
      accessExpiresAt: payload.exp * 1000,
    },
  })
})
