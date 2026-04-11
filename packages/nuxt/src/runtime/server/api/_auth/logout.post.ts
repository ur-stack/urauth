// @ts-nocheck — runtime file: processed by Nitro, not tsc.
// Nitro auto-imports: defineEventHandler, useRuntimeConfig, useSession, $fetch.
// Module auto-imports: clearUserSession (from server/utils/session).
export default defineEventHandler(async (event) => {
  const { session: cfg, public: { urAuth } } = useRuntimeConfig(event)

  // Read the full stored session to get the access token for upstream revocation.
  const stored = await useSession(event, {
    password: cfg.password,
    name: cfg.name,
    maxAge: cfg.maxAge,
    cookie: cfg.cookie,
  })

  // Best-effort upstream logout — revokes the token server-side. Swallow errors
  // so a network hiccup never blocks the local session from being cleared.
  if (stored.data.secure?.accessToken) {
    try {
      await $fetch(`${urAuth.authPrefix}/logout`, {
        baseURL: urAuth.baseURL,
        method: 'POST',
        headers: { Authorization: `Bearer ${stored.data.secure.accessToken}` },
      })
    } catch {}
  }

  return clearUserSession(event)
})
