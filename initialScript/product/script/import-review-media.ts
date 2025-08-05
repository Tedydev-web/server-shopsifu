import { PrismaClient } from '@prisma/client'
import { logger } from './import-utils'

export async function importReviewMedia(
  media: Array<{
    url: string
    type: 'IMAGE' | 'VIDEO'
    reviewId: string
    createdAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (media.length === 0) return
  await tx.reviewMedia.createMany({ data: media, skipDuplicates: true })
  logger.log(`✅ Imported ${media.length} review media`)
}
