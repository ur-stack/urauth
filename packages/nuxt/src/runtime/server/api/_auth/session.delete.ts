// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Clears the server-side session cookie without touching the upstream backend.
// Use /api/_auth/logout to also revoke the refresh token upstream.
export default defineEventHandler(async (event) => {
  return clearUserSession(event)
})
