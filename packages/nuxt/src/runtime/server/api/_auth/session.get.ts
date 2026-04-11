// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Returns the public session (user, roles, permissions) — tokens are never included.
export default defineEventHandler(async (event) => {
  return getUserSession(event)
})
