import { prisma } from '~/server/utils/prisma'

export default defineEventHandler(async (event) => {
  const body = await readBody<{ userId: string, title: string }>(event)
  return prisma.chatSession.create({
    data: { userId: body.userId },
  })
})