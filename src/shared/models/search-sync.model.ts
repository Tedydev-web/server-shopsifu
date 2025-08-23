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
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
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
