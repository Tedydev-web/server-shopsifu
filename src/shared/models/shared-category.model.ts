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
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export const CategoryIncludeTranslationSchema = CategorySchema.extend({
  categoryTranslations: z.array(CategoryTranslationSchema)
})
