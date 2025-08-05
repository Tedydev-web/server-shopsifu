import { PrismaClient } from '@prisma/client'
import { logger, CONFIG } from './import-utils'

export async function importSKUs(
  skus: Array<{
    value: string
    price: number
    stock: number
    image: string
    productId: string
    createdById: string
    createdAt: Date
    updatedAt: Date
  }>,
  tx: PrismaClient
): Promise<void> {
  if (skus.length === 0) return
  const copyBatchSize = CONFIG.SKU_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(skus.length / copyBatchSize) }, (_, i) =>
    skus.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )
  for (const chunk of copyChunks) {
    await tx.sKU.createMany({ data: chunk, skipDuplicates: true })
  }
  logger.log(`✅ Imported ${skus.length} SKUs`)
}
