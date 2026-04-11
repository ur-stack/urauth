// Create a new task (requires task:write permission).
export default defineEventHandler(async (event) => {
  await requireUserPermission(event, 'task', 'write')
  const body = await readBody(event)
  return fetchBackend(event, '/api/v1/tasks', { method: 'POST', body })
})
