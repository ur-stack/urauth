// Delete a task by ID (requires task:delete permission).
export default defineEventHandler(async (event) => {
  await requireUserPermission(event, 'task', 'delete')
  const id = getRouterParam(event, 'id')
  return fetchBackend(event, `/api/v1/tasks/${id}`, { method: 'DELETE' })
})
