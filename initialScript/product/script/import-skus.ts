import { PrismaClient } from '@prisma/client'
import { CONFIG } from './import-utils'

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
  if (skus.length === 0) {
    return
  }

  // Validate dữ liệu SKU
  const validSkus = skus.filter((sku) => {
    if (!sku.value || !sku.value.trim()) {
      return false
    }
    if (sku.price < 0) {
      return false
    }
    if (sku.stock < 0) {
      return false
    }
    return true
  })

  if (validSkus.length === 0) {
    return
  }

  // Kiểm tra SKUs hiện có để tránh duplicate
  const existingSkus = await tx.sKU.findMany({
    where: {
      productId: { in: [...new Set(validSkus.map((s) => s.productId))] },
      deletedAt: null
    },
    select: {
      id: true,
      value: true,
      productId: true
    }
  })

  const existingSkuMap = new Map<string, string>()
  existingSkus.forEach((sku) => {
    existingSkuMap.set(`${sku.productId}-${sku.value}`, sku.id)
  })

  // Lọc ra SKUs mới cần tạo
  const newSkus = validSkus.filter((sku) => {
    const key = `${sku.productId}-${sku.value}`
    return !existingSkuMap.has(key)
  })

  if (newSkus.length === 0) {
    return
  }

  // Import theo batch
  const copyBatchSize = CONFIG.SKU_BATCH_SIZE
  const copyChunks = Array.from({ length: Math.ceil(newSkus.length / copyBatchSize) }, (_, i) =>
    newSkus.slice(i * copyBatchSize, (i + 1) * copyBatchSize)
  )

  let successCount = 0
  let failCount = 0

  for (const chunk of copyChunks) {
    try {
      await tx.sKU.createMany({
        data: chunk,
        skipDuplicates: true
      })
      successCount += chunk.length
    } catch (error) {
      failCount += chunk.length
    }
  }
}
