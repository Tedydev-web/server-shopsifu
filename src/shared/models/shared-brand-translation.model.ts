import { z } from 'zod'

export const BrandTranslationSchema = z.object({
  id: z.number(),
  brandId: z.number(),
  languageId: z.string(),
  name: z.string().max(500),
  description: z.string(),

  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})
