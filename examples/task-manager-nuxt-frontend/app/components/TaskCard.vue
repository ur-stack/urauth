<script setup lang="ts">
interface Task {
  id: number;
  title: string;
  status: string;
  owner_id: number;
  is_public?: boolean;
}

defineProps<{
  task: Task;
  canEdit: boolean;
  canDelete: boolean;
}>();

defineEmits<{
  delete: [id: number];
}>();

const statusColor = (status: string) =>
  ({
    todo: "neutral",
    in_progress: "info",
    done: "success",
  } as Record<string, "neutral" | "info" | "success">)[status] ?? "neutral";

const statusLabel = (status: string) => status.replace("_", " ");
</script>

<template>
  <UCard>
    <div class="flex items-center justify-between gap-3">
      <div class="flex flex-col gap-1 min-w-0">
        <div class="flex items-center gap-2">
          <UButton
            :to="`/tasks/${task.id}`"
            variant="link"
            color="neutral"
            class="font-semibold px-0 text-base truncate"
          >
            {{ task.title }}
          </UButton>
          <UBadge
            :label="statusLabel(task.status)"
            :color="statusColor(task.status)"
            variant="soft"
            size="sm"
          />
          <UBadge
            v-if="task.is_public"
            label="public"
            color="warning"
            variant="soft"
            size="sm"
          />
        </div>
        <p class="text-sm text-muted">owner: {{ task.owner_id }}</p>
      </div>

      <div v-if="canEdit || canDelete" class="flex gap-2 shrink-0">
        <UButton
          v-if="canEdit"
          :to="`/tasks/${task.id}`"
          variant="outline"
          color="primary"
          size="sm"
        >
          Edit
        </UButton>
        <UButton
          v-if="canDelete"
          variant="outline"
          color="error"
          size="sm"
          @click="$emit('delete', task.id)"
        >
          Delete
        </UButton>
      </div>
    </div>
  </UCard>
</template>
