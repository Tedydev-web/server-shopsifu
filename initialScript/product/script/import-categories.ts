import { PrismaClient } from '@prisma/client'
import { ShopeeProduct, CONFIG, logger } from './import-utils'

export async function importCategories(
  products: ShopeeProduct[],
  creatorUserId: string,
  tx: PrismaClient
): Promise<Map<string, string>> {
  const categorySet = new Set<string>(['Khác'])
  const categoryHierarchy = new Map<string, { parent?: string; level: number }>()

  products.forEach((p) => {
    const names = p.breadcrumb.slice(1, -1).slice(0, 3)
    if (names.length) {
      // Thêm category cấp 1
      categorySet.add(names[0])
      categoryHierarchy.set(names[0], { level: 1 })

      // Thêm category cấp 2 (nếu có)
      if (names.length > 1) {
        categorySet.add(names[1])
        categoryHierarchy.set(names[1], { parent: names[0], level: 2 })

        // Thêm category cấp 3 (nếu có)
        if (names.length > 2) {
          categorySet.add(names[2])
          categoryHierarchy.set(names[2], { parent: names[1], level: 3 })
        }
      }
    }
  })

  const existingCategories = await tx.category.findMany({
    where: { name: { in: [...categorySet] }, deletedAt: null },
    select: { id: true, name: true, parentCategoryId: true }
  })
  const categoryMap = new Map(
    existingCategories.map((cat) => [cat.name, { id: cat.id, parentCategoryId: cat.parentCategoryId }])
  )
  const categoriesToCreate = Array.from(categoryHierarchy.entries())
    .filter(([name]) => !categoryMap.has(name))
    .sort((a, b) => a[1].level - b[1].level)

  for (const [name, info] of categoriesToCreate) {
    const parentCategory = info.parent ? categoryMap.get(info.parent) : null
    try {
      const createdCategory = await tx.category.create({
        data: {
          name,
          parentCategoryId: parentCategory ? (parentCategory as any).id : null,
          createdById: creatorUserId
        }
      })

      // 🔑 Cập nhật categoryMap để các category con có thể tìm thấy parent
      categoryMap.set(name, {
        id: createdCategory.id,
        parentCategoryId: parentCategory ? (parentCategory as any).id : null
      })
    } catch (error) {
      logger.warn(`⚠️ Failed to create category: ${name} - ${error}`)
    }
  }
  const finalCategories = await tx.category.findMany({
    where: { name: { in: [...categorySet] }, deletedAt: null },
    select: { id: true, name: true }
  })
  return new Map(finalCategories.map((cat) => [cat.name, cat.id]))
}
