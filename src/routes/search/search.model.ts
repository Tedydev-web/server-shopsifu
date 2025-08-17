import { z } from 'zod'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

/**
 * Schema cho search query
 */
export const SearchProductsQuerySchema = z.object({
  q: z.string().optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(20),
  orderBy: z.nativeEnum(OrderBy).default(OrderBy.Desc),
  sortBy: z.nativeEnum(SortBy).default(SortBy.CreatedAt),
  filters: z
    .object({
      brandIds: z
        .preprocess((value) => {
          if (typeof value === 'string') {
            return [value]
          }
          return value
        }, z.array(z.string()))
        .optional(),
      categoryIds: z
        .preprocess((value) => {
          if (typeof value === 'string') {
            return [value]
          }
          return value
        }, z.array(z.string()))
        .optional(),
      minPrice: z.coerce.number().positive().optional(),
      maxPrice: z.coerce.number().positive().optional(),
      attrs: z
        .array(
          z.object({
            attrName: z.string(),
            attrValue: z.string()
          })
        )
        .optional()
    })
    .optional()
})

/**
 * Schema cho search response
 */
export const SearchProductsResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    z.object({
      skuId: z.string(),
      productId: z.string(),
      skuValue: z.string(),
      skuPrice: z.number(),
      skuStock: z.number(),
      skuImage: z.string().optional(),
      productName: z.string().optional(),
      productDescription: z.string().optional(),
      productImages: z.array(z.string()).optional(),
      brandId: z.string().optional(),
      brandName: z.string().optional(),
      categoryIds: z.array(z.string()).optional(),
      categoryNames: z.array(z.string()).optional(),
      specifications: z.any().optional(),
      variants: z.any().optional(),
      attrs: z
        .array(
          z.object({
            attrName: z.string(),
            attrValue: z.string()
          })
        )
        .optional(),
      createdAt: z.union([z.string(), z.date()]).optional(),
      updatedAt: z.union([z.string(), z.date()]).optional()
    })
  ),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

// Type exports
export type SearchProductsQueryType = z.infer<typeof SearchProductsQuerySchema>
export type SearchProductsResType = z.infer<typeof SearchProductsResSchema>
