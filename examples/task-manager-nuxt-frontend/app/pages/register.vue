<script setup lang="ts">
const { isAuthenticated } = useAuth();

if (isAuthenticated.value) {
  await navigateTo("/tasks");
}

const username = ref("");
const password = ref("");
const confirmPassword = ref("");
const error = ref<string | null>(null);
const pending = ref(false);

async function handleSubmit() {
  if (!username.value || !password.value) return;

  if (password.value !== confirmPassword.value) {
    error.value = "Passwords do not match";
    return;
  }

  error.value = null;
  pending.value = true;

  try {
    // /api/_auth/register auto-logs in after registration and sets the session.
    await $fetch("/api/_auth/register", {
      method: "POST",
      body: { username: username.value, password: password.value },
    });
    await navigateTo("/tasks");
  } catch (err: unknown) {
    const fetchErr = err as { data?: { message?: string }; message?: string };
    error.value =
      fetchErr.data?.message ?? fetchErr.message ?? "Registration failed";
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <div class="flex justify-center pt-12">
    <UCard class="w-full max-w-sm">
      <template #header>
        <h1 class="text-xl font-semibold">Create account</h1>
        <p class="text-sm text-muted mt-1">
          Already have one?
          <UButton to="/login" variant="link" color="primary" class="px-0">
            Sign in
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
            autocomplete="new-password"
            placeholder="Password"
            class="w-full"
          />
        </UFormField>

        <UFormField label="Confirm password" required>
          <UInput
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            placeholder="Confirm password"
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
          Create account
        </UButton>
      </form>

      <template #footer>
        <p class="text-xs text-muted">
          New accounts receive the <strong>viewer</strong> role — they can read
          tasks. An admin must promote you to <strong>editor</strong> to create
          or update tasks.
        </p>
      </template>
    </UCard>
  </div>
</template>
