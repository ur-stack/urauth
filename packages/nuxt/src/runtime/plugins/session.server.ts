// @ts-nocheck — runtime file: processed by Nuxt (server-only plugin), not tsc.
// Nuxt auto-imports: defineNuxtPlugin, useState, useRequestEvent.
// Imports getUserSession directly — this file is bundled into Nitro where the
// server utility is available.
import { getUserSession } from '../server/utils/session'

/**
 * Server-only plugin: seeds useState('urauth:session') from the real session
 * cookie on each SSR request so the first paint is already hydrated.
 *
 * Without this, useAuth().isAuthenticated would be false on the server and cause a
 * hydration flash on the client.
 */
export default defineNuxtPlugin(async () => {
  const event = useRequestEvent()
  if (!event) return

  const session = useState('urauth:session', () => ({
    user: undefined,
    roles: [],
    permissions: [],
    loggedInAt: 0,
  }))
  const ready = useState('urauth:ready', () => false)

  try {
    session.value = await getUserSession(event)
  } catch {}

  ready.value = true
})
