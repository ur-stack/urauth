// Fetch a single task by ID.
export default defineEventHandler(async (event) => {
  await requireUserSession(event)
  const id = getRouterParam(event, 'id')
  return fetchBackend(event, `/api/v1/tasks/${id}`)
})
