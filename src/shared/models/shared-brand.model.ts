import { BrandTranslationSchema } from 'src/shared/models/shared-brand-translation.model'
import { z } from 'zod'

export const BrandSchema = z.object({
  id: z.string(),
  name: z.string().max(500),
  logo: z.string().url().max(1000),

  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const BrandIncludeTranslationSchema = BrandSchema.extend({
  brandTranslations: z.array(BrandTranslationSchema)
})
