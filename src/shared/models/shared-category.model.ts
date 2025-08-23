import { CategoryTranslationSchema } from 'src/shared/models/shared-category-translation.model'
import { z } from 'zod'

export const CategorySchema = z.object({
  id: z.string(),
  parentCategoryId: z.string().nullable(),
  name: z.string(),
  logo: z.string().nullable(),

  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const CategoryIncludeTranslationSchema = CategorySchema.extend({
  categoryTranslations: z.array(CategoryTranslationSchema)
})
