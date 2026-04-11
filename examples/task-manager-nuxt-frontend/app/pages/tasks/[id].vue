<script setup lang="ts">
definePageMeta({ middleware: "auth" });

const route = useRoute();
const { can } = useAuth();

const taskId = computed(() => route.params.id as string);

const canEdit = computed(() => can("task", "update"));

interface TaskDetail {
  id: number;
  title: string;
  description: string | null;
  status: string;
  owner_id: number;
  is_public: boolean;
}

// Fetch via the local Nitro proxy — cookie auth is automatic.
const { data: task, status, error, refresh } = await useFetch<TaskDetail>(
  () => `/api/tasks/${taskId.value}`,
);

// Edit form state — mirrored from the fetched task.
const editing = ref(false);
const editTitle = ref("");
const editStatus = ref<string>("todo");
const updateError = ref<string | null>(null);
const updating = ref(false);

const statusOptions = [
  { label: "To do", value: "todo" },
  { label: "In progress", value: "in_progress" },
  { label: "Done", value: "done" },
];

const statusColor = (s: string) =>
  ({ todo: "neutral", in_progress: "info", done: "success" } as Record<
    string,
    "neutral" | "info" | "success"
  >)[s] ?? "neutral";

function startEdit() {
  if (!task.value) return;
  editTitle.value = task.value.title;
  editStatus.value = task.value.status;
  editing.value = true;
}

function cancelEdit() {
  editing.value = false;
  updateError.value = null;
}

async function saveEdit() {
  if (!task.value) return;
  updateError.value = null;
  updating.value = true;

  try {
    await $fetch(`/api/tasks/${task.value.id}`, {
      method: "PUT",
      body: { title: editTitle.value, status: editStatus.value },
    });
    editing.value = false;
    await refresh();
  } catch (err: unknown) {
    updateError.value =
      err instanceof Error ? err.message : "Failed to update task";
  } finally {
    updating.value = false;
  }
}
</script>

<template>
  <div class="flex flex-col gap-4">
    <UButton
      to="/tasks"
      variant="ghost"
      color="neutral"
      icon="i-lucide-arrow-left"
      class="self-start"
    >
      All tasks
    </UButton>

    <!-- Loading -->
    <p v-if="status === 'pending'" class="text-muted py-8">Loading…</p>

    <!-- Error -->
    <UAlert
      v-else-if="error"
      description="Task not found or you do not have permission to view it."
      color="error"
      variant="soft"
      icon="i-lucide-circle-x"
    />

    <UCard v-else-if="task">
      <!-- View mode -->
      <template v-if="!editing">
        <template #header>
          <div class="flex items-start justify-between gap-3">
            <h1 class="text-xl font-semibold">{{ task.title }}</h1>
            <div class="flex gap-2 shrink-0">
              <UBadge
                :label="task.status.replace('_', ' ')"
                :color="statusColor(task.status)"
                variant="soft"
              />
              <UBadge
                v-if="task.is_public"
                label="public"
                color="warning"
                variant="soft"
              />
            </div>
          </div>
        </template>

        <p v-if="task.description" class="text-muted">{{ task.description }}</p>
        <p class="text-sm text-muted mt-2">Owner ID: {{ task.owner_id }}</p>

        <template #footer>
          <UButton
            v-if="canEdit"
            variant="outline"
            color="primary"
            @click="startEdit"
          >
            Edit task
          </UButton>
        </template>
      </template>

      <!-- Edit mode (editor/admin only) -->
      <template v-else>
        <template #header>
          <h1 class="text-xl font-semibold">Edit task</h1>
        </template>

        <form class="flex flex-col gap-4" @submit.prevent="saveEdit">
          <UFormField label="Title" required>
            <UInput v-model="editTitle" type="text" required class="w-full" />
          </UFormField>

          <UFormField label="Status">
            <USelect
              v-model="editStatus"
              :items="statusOptions"
              value-key="value"
              class="w-full"
            />
          </UFormField>

          <UAlert
            v-if="updateError"
            :description="updateError"
            color="error"
            variant="soft"
            icon="i-lucide-circle-x"
          />

          <div class="flex gap-3">
            <UButton
              type="button"
              variant="outline"
              color="neutral"
              @click="cancelEdit"
            >
              Cancel
            </UButton>
            <UButton type="submit" :loading="updating" :disabled="updating">
              Save changes
            </UButton>
          </div>
        </form>
      </template>
    </UCard>
  </div>
</template>
