import { BrandIncludeTranslationSchema, BrandSchema } from 'src/shared/models/shared-brand.model'
import { z } from 'zod'

export const GetBrandsResSchema = z.object({
  message: z.string().optional(),
  data: z.array(BrandIncludeTranslationSchema),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const GetBrandParamsSchema = z
  .object({
    brandId: z.string()
  })
  .strict()

export const GetBrandDetailResSchema = z.object({
  message: z.string().optional(),
  data: BrandIncludeTranslationSchema
})

export const CreateBrandBodySchema = BrandSchema.pick({
  name: true,
  logo: true
}).strict()

export const UpdateBrandBodySchema = CreateBrandBodySchema.partial()

export type BrandType = z.infer<typeof BrandSchema>
export type BrandIncludeTranslationType = z.infer<typeof BrandIncludeTranslationSchema>
export type GetBrandsResType = z.infer<typeof GetBrandsResSchema>
export type GetBrandDetailResType = z.infer<typeof GetBrandDetailResSchema>
export type CreateBrandBodyType = z.infer<typeof CreateBrandBodySchema>
export type GetBrandParamsType = z.infer<typeof GetBrandParamsSchema>
export type UpdateBrandBodyType = z.infer<typeof UpdateBrandBodySchema>
