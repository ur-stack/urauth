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

  let res
  try {
    res = await $fetch(`${authPrefix}/login`, {
      baseURL,
      method: 'POST',
      body: { username: body.username, password: body.password },
    })
  } catch (err) {
    throw createError({
      statusCode: err?.status ?? err?.statusCode ?? 401,
      message: 'Invalid credentials',
    })
  }

  const payload = decodeJWT(res.access_token)

  return setUserSession(event, {
    user: { id: payload.sub },
    roles: payload.roles ?? [],
    permissions: payload.permissions ?? [],
    loggedInAt: Date.now(),
    secure: {
      accessToken: res.access_token,
      refreshToken: res.refresh_token,
      accessExpiresAt: payload.exp * 1000,
    },
  })
})
