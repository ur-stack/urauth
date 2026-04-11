<script setup lang="ts">
const { isAuthenticated } = useAuth();

// Redirect on the client after hydration; middleware handles server-side.
if (isAuthenticated.value) {
  await navigateTo("/tasks");
} else {
  await navigateTo("/login");
}
</script>

<template>
  <!-- Redirect page — no visible content -->
  <div />
</template>
