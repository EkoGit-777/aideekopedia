import { askGemini } from '~/server/utils/ai'

export default defineEventHandler(async (event) => {
  const body = await readBody<{ prompt: string }>(event)
  if (!body?.prompt) {
    throw createError({ statusCode: 400, message: 'Missing prompt' })
  }

  const reply = await askGemini(body.prompt)
  return { reply }
})