import { CategoryIncludeTranslationSchema, CategorySchema } from 'src/shared/models/shared-category.model'
import { z } from 'zod'
import { BasePaginationQuerySchema, PaginationMetadataSchema } from 'src/shared/models/pagination.model'

export const GetAllCategoriesResSchema = z.object({
  data: z.array(CategorySchema),
  metadata: PaginationMetadataSchema,
})

export const GetAllCategoriesQuerySchema = BasePaginationQuerySchema.extend({
  parentCategoryId: z.coerce.number().int().positive().optional(),
  sortBy: z.enum(['name', 'createdAt']).optional(),
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
