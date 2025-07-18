import { z } from 'zod'

export const ProductTranslationSchema = z.object({
  id: z.string(),
  productId: z.string(),
  name: z.string().max(500),
  description: z.string().max(1000),
  languageId: z.string(),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type ProductTranslationType = z.infer<typeof ProductTranslationSchema>
