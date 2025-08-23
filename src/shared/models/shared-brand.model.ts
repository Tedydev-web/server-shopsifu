import { BrandTranslationSchema } from 'src/shared/models/shared-brand-translation.model'
import { z } from 'zod'

export const BrandSchema = z.object({
  id: z.string(),
  name: z.string().max(500),
  logo: z.string().max(1000),

  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const BrandIncludeTranslationSchema = BrandSchema.extend({
  brandTranslations: z.array(BrandTranslationSchema)
})
