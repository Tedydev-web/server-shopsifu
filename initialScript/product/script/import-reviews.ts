import { PrismaClient } from '@prisma/client'
import { logger } from './import-utils'

export async function importReviews(
  reviews: Array<{
    rating: number
    content: string
    userId: string
    productId: string
    orderId: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<string[]> {
  if (reviews.length === 0) return []
  await tx.review.createMany({ data: reviews, skipDuplicates: true })
  const createdReviews = await tx.review.findMany({
    where: {
      productId: { in: reviews.map((r) => r.productId) },
      orderId: { in: reviews.map((r) => r.orderId) }
    },
    select: { id: true },
    orderBy: { createdAt: 'desc' },
    take: reviews.length
  })
  logger.log(`✅ Imported ${createdReviews.length} reviews`)
  return createdReviews.map((r) => r.id)
}
