import { PrismaClient } from '@prisma/client'
import { ShopeeProduct, CONFIG, logger } from './import-utils'

export async function importBrands(
  products: ShopeeProduct[],
  creatorUserId: string,
  tx: PrismaClient
): Promise<Map<string, string>> {
  const uniqueBrandNames = [...new Set(products.map((p) => p.brand || CONFIG.DEFAULT_BRAND_NAME))]
  const existingBrands = await tx.brand.findMany({
    where: { deletedAt: null, name: { in: uniqueBrandNames } },
    select: { id: true, name: true }
  })
  const existingBrandNames = new Set(existingBrands.map((b) => b.name))
  await tx.brand.updateMany({
    where: { deletedAt: null, name: { notIn: uniqueBrandNames } },
    data: { deletedAt: new Date() }
  })
  const newBrands = uniqueBrandNames.filter((name) => !existingBrandNames.has(name))
  if (newBrands.length) {
    await tx.brand.createMany({
      data: newBrands.map((name) => ({ name, logo: CONFIG.DEFAULT_AVATAR, createdById: creatorUserId })),
      skipDuplicates: true
    })
  }
  const allBrands = await tx.brand.findMany({
    where: { name: { in: uniqueBrandNames }, deletedAt: null },
    select: { id: true, name: true }
  })
  logger.log(`✅ Imported ${allBrands.length} brands`)
  return new Map(allBrands.map((brand) => [brand.name, brand.id]))
}
