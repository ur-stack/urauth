<script setup lang="ts">
const { isAuthenticated, user, roles, logout } = useAuth();
</script>

<template>
  <UHeader>
    <template #left>
      <UButton
        to="/"
        variant="link"
        color="neutral"
        class="font-bold text-base px-0"
      >
        urauth tasks
      </UButton>
    </template>

    <template #right>
      <template v-if="isAuthenticated">
        <UButton to="/tasks" variant="ghost" color="neutral" size="sm">
          Tasks
        </UButton>
        <span class="text-sm text-muted">{{ user?.id }}</span>
        <UBadge
          v-for="role in roles"
          :key="role"
          :label="role"
          variant="soft"
          color="primary"
          size="sm"
        />
        <UButton variant="outline" color="neutral" size="sm" @click="logout">
          Sign out
        </UButton>
      </template>
      <template v-else>
        <UButton to="/login" variant="ghost" color="neutral" size="sm">
          Sign in
        </UButton>
        <UButton to="/register" variant="solid" color="primary" size="sm">
          Register
        </UButton>
      </template>
    </template>
  </UHeader>
</template>
