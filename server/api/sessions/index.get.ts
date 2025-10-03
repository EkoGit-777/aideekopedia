import { prisma } from '~/server/utils/prisma'

export default defineEventHandler(async () => {
  return prisma.chatSession.findMany({
    include: { messages: true, user: true },
  })
})