import { z } from 'zod'

/**
 * Schema cho ES document attributes
 */
export const EsAttributeSchema = z.object({
  attrName: z.string(),
  attrValue: z.string()
})

export type EsAttributeType = z.infer<typeof EsAttributeSchema>

/**
 * Schema cho ES product document
 */
export const EsProductDocumentSchema = z.object({
  skuId: z.string(),
  productId: z.string(),
  skuValue: z.string(),
  skuPrice: z.number(),
  skuStock: z.number(),
  skuImage: z.string(),
  productName: z.string(),
  productDescription: z.string(),
  productImages: z.array(z.string()),
  brandId: z.string(),
  brandName: z.string(),
  categoryIds: z.array(z.string()),
  categoryNames: z.array(z.string()),
  specifications: z.any().optional(),
  variants: z.any().optional(),
  attrs: z.array(EsAttributeSchema),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type EsProductDocumentType = z.infer<typeof EsProductDocumentSchema>

/**
 * Schema cho sync job data
 */
export const SyncProductJobSchema = z.object({
  productId: z.string(),
  action: z.enum(['create', 'update', 'delete'])
})

export type SyncProductJobType = z.infer<typeof SyncProductJobSchema>

/**
 * Schema cho batch sync job data
 */
export const SyncProductsBatchJobSchema = z.object({
  productIds: z.array(z.string()),
  action: z.enum(['create', 'update', 'delete'])
})

export type SyncProductsBatchJobType = z.infer<typeof SyncProductsBatchJobSchema>

/**
 * Schema cho search query
 */
export const SearchQuerySchema = z.object({
  q: z.string().optional(),
  filters: z
    .object({
      brandIds: z.array(z.string()).optional(),
      categoryIds: z.array(z.string()).optional(),
      minPrice: z.number().optional(),
      maxPrice: z.number().optional(),
      attrs: z.array(EsAttributeSchema).optional()
    })
    .optional(),
  pagination: z
    .object({
      page: z.number().min(1).default(1),
      limit: z.number().min(1).max(100).default(20)
    })
    .optional(),
  sort: z
    .object({
      field: z.enum(['skuPrice', 'createdAt', 'updatedAt', '_score']).default('_score'),
      order: z.enum(['asc', 'desc']).default('desc')
    })
    .optional()
})

export type SearchQueryType = z.infer<typeof SearchQuerySchema>
