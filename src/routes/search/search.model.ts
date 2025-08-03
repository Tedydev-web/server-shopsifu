import { z } from 'zod'

/**
 * Schema cho search query
 */
export const SearchProductsQuerySchema = z.object({
  q: z.string().optional(),
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
    totalItems: z.number()
  })
})

/**
 * Schema cho sync job
 */
export const SyncProductJobSchema = z.object({
  productId: z.string(),
  action: z.enum(['create', 'update', 'delete'])
})

export const SyncProductsBatchJobSchema = z.object({
  productIds: z.array(z.string()),
  action: z.enum(['create', 'update', 'delete'])
})

/**
 * Schema cho queue info response
 */
export const QueueInfoResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    waiting: z.number(),
    active: z.number(),
    completed: z.number(),
    failed: z.number()
  })
})

// Type exports
export type SearchProductsQueryType = z.infer<typeof SearchProductsQuerySchema>
export type SearchProductsResType = z.infer<typeof SearchProductsResSchema>
export type SyncProductJobType = z.infer<typeof SyncProductJobSchema>
export type SyncProductsBatchJobType = z.infer<typeof SyncProductsBatchJobSchema>
export type QueueInfoResType = z.infer<typeof QueueInfoResSchema>
