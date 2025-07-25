import { z } from 'zod'

export const BrandTranslationSchema = z.object({
  id: z.string(),
  brandId: z.string(),
  languageId: z.string(),
  name: z.string().max(500),
  description: z.string(),

  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})
