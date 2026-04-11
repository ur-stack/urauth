<script setup lang="ts">
const { login, isAuthenticated } = useAuth();

// Already authenticated — skip the login page.
if (isAuthenticated.value) {
  await navigateTo("/tasks");
}

const username = ref("");
const password = ref("");
const error = ref<string | null>(null);
const pending = ref(false);

async function handleSubmit() {
  if (!username.value || !password.value) return;
  error.value = null;
  pending.value = true;

  try {
    await login({ username: username.value, password: password.value });
    await navigateTo("/tasks");
  } catch (err: unknown) {
    error.value =
      err instanceof Error ? err.message : "Invalid username or password";
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <div class="flex justify-center pt-12">
    <UCard class="w-full max-w-sm">
      <template #header>
        <h1 class="text-xl font-semibold">Sign in</h1>
        <p class="text-sm text-muted mt-1">
          New here?
          <UButton to="/register" variant="link" color="primary" class="px-0">
            Create an account
          </UButton>
        </p>
      </template>

      <form class="flex flex-col gap-4" @submit.prevent="handleSubmit">
        <UFormField label="Username" required>
          <UInput
            v-model="username"
            type="text"
            autocomplete="username"
            placeholder="Username"
            class="w-full"
          />
        </UFormField>

        <UFormField label="Password" required>
          <UInput
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="Password"
            class="w-full"
          />
        </UFormField>

        <UAlert
          v-if="error"
          :description="error"
          color="error"
          variant="soft"
          icon="i-lucide-circle-x"
        />

        <UButton
          type="submit"
          :loading="pending"
          :disabled="pending"
          block
        >
          Sign in
        </UButton>
      </form>
    </UCard>
  </div>
</template>
