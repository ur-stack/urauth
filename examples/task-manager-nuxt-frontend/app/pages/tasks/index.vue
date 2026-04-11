<script setup lang="ts">
definePageMeta({ middleware: "auth" });

const { can } = useAuth();

const canWrite = computed(() => can("task", "write"));
const canDelete = computed(() => can("task", "delete"));

interface Task {
  id: number;
  title: string;
  status: string;
  owner_id: number;
  is_public?: boolean;
}

// Fetch via the local Nitro proxy — the browser never touches the backend directly.
const {
  data: tasks,
  status,
  error,
  refresh,
} = await useFetch<Task[]>("/api/tasks");

// Create task form
const showForm = ref(false);
const newTitle = ref("");
const createError = ref<string | null>(null);
const creating = ref(false);

async function createTask() {
  if (!newTitle.value.trim()) return;
  createError.value = null;
  creating.value = true;

  try {
    await $fetch("/api/tasks", {
      method: "POST",
      body: { title: newTitle.value.trim() },
    });
    newTitle.value = "";
    showForm.value = false;
    await refresh();
  } catch (err: unknown) {
    createError.value =
      err instanceof Error ? err.message : "Failed to create task";
  } finally {
    creating.value = false;
  }
}

async function deleteTask(id: number) {
  try {
    await $fetch(`/api/tasks/${id}`, { method: "DELETE" });
    await refresh();
  } catch {
    // Silently ignore — the list will be stale; user can refresh.
  }
}
</script>

<template>
  <div class="flex flex-col gap-6">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-semibold">Tasks</h1>
      <UButton
        v-if="canWrite"
        :variant="showForm ? 'outline' : 'solid'"
        :color="showForm ? 'neutral' : 'primary'"
        @click="showForm = !showForm"
      >
        {{ showForm ? "Cancel" : "New task" }}
      </UButton>
    </div>

    <!-- Create form (editor/admin only) -->
    <UCard v-if="showForm && canWrite">
      <form class="flex gap-3" @submit.prevent="createTask">
        <UInput
          v-model="newTitle"
          type="text"
          placeholder="Task title"
          class="flex-1"
          required
        />
        <UButton type="submit" :loading="creating" :disabled="creating">
          Create
        </UButton>
      </form>
      <UAlert
        v-if="createError"
        :description="createError"
        color="error"
        variant="soft"
        icon="i-lucide-circle-x"
        class="mt-3"
      />
    </UCard>

    <!-- Loading -->
    <p v-if="status === 'pending'" class="text-center text-muted py-8">
      Loading tasks…
    </p>

    <!-- Error -->
    <UAlert
      v-else-if="error"
      :description="`Failed to load tasks: ${error.message}`"
      color="error"
      variant="soft"
      icon="i-lucide-circle-x"
    />

    <!-- Empty -->
    <p v-else-if="tasks && tasks.length === 0" class="text-center text-muted py-8">
      No tasks yet.
    </p>

    <!-- Task list -->
    <div v-else class="flex flex-col gap-3">
      <TaskCard
        v-for="task in tasks"
        :key="task.id"
        :task="task"
        :can-edit="canWrite"
        :can-delete="canDelete"
        @delete="deleteTask"
      />
    </div>
  </div>
</template>
