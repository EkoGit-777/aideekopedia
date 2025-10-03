import { prisma } from '~/server/utils/prisma'

export default defineEventHandler(async (event) => {
  const body = await readBody<{ userId: string }>(event)
  return prisma.chatSession.create({
    data: { userId: body.userId },
  })
})