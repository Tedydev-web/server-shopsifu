import { CategoryTranslationSchema } from 'src/shared/models/shared-category-translation.model'
import { z } from 'zod'

export const GetCategoryTranslationParamsSchema = z
  .object({
    categoryTranslationId: z.coerce.number().int().positive(),
  })
  .strict()
export const GetCategoryTranslationDetailResSchema = CategoryTranslationSchema
export const CreateCategoryTranslationBodySchema = CategoryTranslationSchema.pick({
  categoryId: true,
  languageId: true,
  name: true,
  description: true,
}).strict()
export const UpdateCategoryTranslationBodySchema = CreateCategoryTranslationBodySchema

export type CategoryTranslationType = z.infer<typeof CategoryTranslationSchema>
export type GetCategoryTranslationDetailResType = z.infer<typeof GetCategoryTranslationDetailResSchema>
export type CreateCategoryTranslationBodyType = z.infer<typeof CreateCategoryTranslationBodySchema>
export type UpdateCategoryTranslationBodyType = z.infer<typeof UpdateCategoryTranslationBodySchema>
