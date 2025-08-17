import { BrandTranslationSchema } from 'src/shared/models/shared-brand-translation.model'
import { z } from 'zod'

export const GetBrandTranslationParamsSchema = z
  .object({
    brandTranslationId: z.string()
  })
  .strict()

export const GetBrandTranslationDetailResSchema = z.object({
  data: BrandTranslationSchema,
  message: z.string().optional()
})

export const CreateBrandTranslationBodySchema = BrandTranslationSchema.pick({
  brandId: true,
  languageId: true,
  name: true,
  description: true
}).strict()

export const UpdateBrandTranslationBodySchema = CreateBrandTranslationBodySchema.partial()

export type BrandTranslationType = z.infer<typeof BrandTranslationSchema>
export type GetBrandTranslationDetailResType = z.infer<typeof GetBrandTranslationDetailResSchema>
export type CreateBrandTranslationBodyType = z.infer<typeof CreateBrandTranslationBodySchema>
export type UpdateBrandTranslationBodyType = z.infer<typeof UpdateBrandTranslationBodySchema>
