import { ProductTranslationSchema } from 'src/shared/models/shared-product-translation.model'
import { z } from 'zod'

export const GetProductTranslationParamsSchema = z
  .object({
    productTranslationId: z.coerce.number().int().positive(),
  })
  .strict()

export const GetProductTranslationDetailResSchema = ProductTranslationSchema

export const CreateProductTranslationBodySchema = ProductTranslationSchema.pick({
  productId: true,
  name: true,
  description: true,
  languageId: true,
}).strict()

export const UpdateProductTranslationBodySchema = CreateProductTranslationBodySchema

export const DeleteProductTranslationParamsSchema = GetProductTranslationParamsSchema

export type GetProductTranslationParamsType = z.infer<typeof GetProductTranslationParamsSchema>
export type GetProductTranslationDetailResType = z.infer<typeof GetProductTranslationDetailResSchema>
export type CreateProductTranslationBodyType = z.infer<typeof CreateProductTranslationBodySchema>
export type UpdateProductTranslationBodyType = z.infer<typeof UpdateProductTranslationBodySchema>
export type DeleteProductTranslationParamsType = z.infer<typeof DeleteProductTranslationParamsSchema>
