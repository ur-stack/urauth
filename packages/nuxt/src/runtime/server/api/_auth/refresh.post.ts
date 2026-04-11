// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Module auto-imports: refreshSession, getUserSession (from server/utils).
export default defineEventHandler(async (event) => {
  const newAccess = await refreshSession(event)
  if (!newAccess) {
    throw createError({ statusCode: 401, message: 'Token refresh failed' })
  }
  return getUserSession(event)
})
