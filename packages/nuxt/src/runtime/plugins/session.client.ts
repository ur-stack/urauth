// @ts-nocheck — runtime file: processed by Nuxt (client-only plugin), not tsc.
// Nuxt auto-imports: defineNuxtPlugin, useState.

/**
 * Client-only plugin: fetches the session from /api/_auth/session on mount
 * if the server plugin didn't already hydrate it (e.g. static/SPA mode).
 */
export default defineNuxtPlugin(async () => {
  const ready = useState('urauth:ready', () => false)
  if (ready.value) return // SSR already seeded the state — nothing to do.

  const { fetch } = useAuth()
  try {
    await fetch()
  } catch {}
})
