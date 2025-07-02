import { z } from 'zod'

export const BrandTranslationSchema = z.object({
  id: z.number(),
  brandId: z.number(),
  languageId: z.string(),
  name: z.string().max(500),
  description: z.string(),

  createdById: z.number().nullable(),
  updatedById: z.number().nullable(),
  deletedById: z.number().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date(),
})
export const GetBrandTranslationParamsSchema = z
  .object({
    brandTranslationId: z.coerce.number().int().positive(),
  })
  .strict()
export const GetBrandTranslationDetailResSchema = BrandTranslationSchema
export const CreateBrandTranslationBodySchema = BrandTranslationSchema.pick({
  brandId: true,
  languageId: true,
  name: true,
  description: true,
}).strict()
export const UpdateBrandTranslationBodySchema = CreateBrandTranslationBodySchema

export type BrandTranslationType = z.infer<typeof BrandTranslationSchema>
export type GetBrandTranslationDetailResType = z.infer<typeof GetBrandTranslationDetailResSchema>
export type CreateBrandTranslationBodyType = z.infer<typeof CreateBrandTranslationBodySchema>
export type UpdateBrandTranslationBodyType = z.infer<typeof UpdateBrandTranslationBodySchema>
