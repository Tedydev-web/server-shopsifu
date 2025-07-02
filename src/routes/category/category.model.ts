import { CategoryTranslationSchema } from 'src/routes/category/category-translation/category-translation.model'
import { z } from 'zod'

export const CategorySchema = z.object({
  id: z.number(),
  parentCategoryId: z.number().nullable(),
  name: z.string(),
  logo: z.string().nullable(),

  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})

const CategoryIncludeTranslationSchema = CategorySchema.extend({
  categoryTranslations: z.array(CategoryTranslationSchema),
})

export const GetAllCategoriesResSchema = z.object({
  data: z.array(CategorySchema),
  totalItems: z.number(),
})

export const GetAllCategoriesQuerySchema = z.object({
  parentCategoryId: z.coerce.number().int().positive().optional(),
})

export const GetCategoryParamsSchema = z
  .object({
    categoryId: z.coerce.number().int().positive(),
  })
  .strict()

export const GetCategoryDetailResSchema = CategoryIncludeTranslationSchema

export const CreateCategoryBodySchema = CategorySchema.pick({
  name: true,
  logo: true,
  parentCategoryId: true,
}).strict()

export const UpdateCategoryBodySchema = CreateCategoryBodySchema

export type CategoryType = z.infer<typeof CategorySchema>
export type CategoryIncludeTranslationType = z.infer<typeof CategoryIncludeTranslationSchema>
export type GetAllCategoriesResType = z.infer<typeof GetAllCategoriesResSchema>
export type GetAllCategoriesQueryType = z.infer<typeof GetAllCategoriesQuerySchema>
export type GetCategoryDetailResType = z.infer<typeof GetCategoryDetailResSchema>
export type CreateCategoryBodyType = z.infer<typeof CreateCategoryBodySchema>
export type GetCategoryParamsType = z.infer<typeof GetCategoryParamsSchema>
export type UpdateCategoryBodyType = z.infer<typeof UpdateCategoryBodySchema>
