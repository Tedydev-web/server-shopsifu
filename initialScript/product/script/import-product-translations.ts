import { PrismaClient } from '@prisma/client'
import { logger, CONFIG } from './import-utils'

export async function importProductTranslations(
  translations: Array<{
    productId: string
    languageId: string
    name: string
    description: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (translations.length === 0) return
  await tx.productTranslation.createMany({ data: translations, skipDuplicates: true })
  logger.log(`✅ Imported ${translations.length} product translations`)
}
