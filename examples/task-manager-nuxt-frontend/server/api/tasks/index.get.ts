// List all tasks the current user can access.
export default defineEventHandler(async (event) => {
  await requireUserSession(event)
  return fetchBackend(event, '/api/v1/tasks')
})
