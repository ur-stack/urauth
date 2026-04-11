/**
 * auth middleware — redirects unauthenticated users to /login.
 *
 * Apply to protected pages with: definePageMeta({ middleware: "auth" })
 */
export default defineNuxtRouteMiddleware(() => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated.value) {
    return navigateTo("/login");
  }
});
