import { CategoryIncludeTranslationSchema, CategorySchema } from 'src/shared/models/shared-category.model'
import { z } from 'zod'

export const GetAllCategoriesResSchema = z.object({
  message: z.string().optional(),
  data: z.array(CategorySchema),
  totalItems: z.number()
})

export const GetAllCategoriesQuerySchema = z.object({
  parentCategoryId: z.string().optional()
})

export const GetCategoryParamsSchema = z
  .object({
    categoryId: z.string()
  })
  .strict()

export const GetCategoryDetailResSchema = z.object({
  data: CategoryIncludeTranslationSchema,
  message: z.string().optional()
})

export const CreateCategoryBodySchema = CategorySchema.pick({
  name: true,
  logo: true,
  parentCategoryId: true
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
