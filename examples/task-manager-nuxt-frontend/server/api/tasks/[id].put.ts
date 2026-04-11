// Update a task by ID (requires task:update permission).
export default defineEventHandler(async (event) => {
  await requireUserPermission(event, 'task', 'update')
  const id = getRouterParam(event, 'id')
  const body = await readBody(event)
  return fetchBackend(event, `/api/v1/tasks/${id}`, { method: 'PUT', body })
})
