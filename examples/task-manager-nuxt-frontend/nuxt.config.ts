// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: "2025-01-01",
  devtools: { enabled: true },

  modules: ["@nuxt/ui", "@urauth/nuxt"],

  // @urauth/nuxt module options.
  // Override baseURL at runtime via NUXT_PUBLIC_UR_AUTH_BASE_URL.
  // Override the session password via NUXT_SESSION_PASSWORD (≥32 chars, required in production).
  urAuth: {
    baseURL: process.env.NUXT_PUBLIC_UR_AUTH_BASE_URL ?? "http://localhost:8000",
    authPrefix: "/api/v1/auth",
    routes: { register: true },
  },

  typescript: {
    strict: true,
  },
});
