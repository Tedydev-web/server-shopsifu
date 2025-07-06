import { BrandIncludeTranslationSchema, BrandSchema } from 'src/shared/models/shared-brand.model'
import { z } from 'zod'
import { PaginationMetadataSchema } from 'src/shared/models/pagination.model'

export const GetBrandsResSchema = z.object({
  data: z.array(BrandIncludeTranslationSchema),
  metadata: PaginationMetadataSchema
})

export const GetBrandParamsSchema = z
  .object({
    brandId: z.coerce.number().int().positive()
  })
  .strict()

export const GetBrandDetailResSchema = BrandIncludeTranslationSchema

export const CreateBrandBodySchema = BrandSchema.pick({
  name: true,
  logo: true
}).strict()

export const UpdateBrandBodySchema = CreateBrandBodySchema

export type BrandType = z.infer<typeof BrandSchema>
export type BrandIncludeTranslationType = z.infer<typeof BrandIncludeTranslationSchema>
export type GetBrandsResType = z.infer<typeof GetBrandsResSchema>
export type GetBrandDetailResType = z.infer<typeof GetBrandDetailResSchema>
export type CreateBrandBodyType = z.infer<typeof CreateBrandBodySchema>
export type GetBrandParamsType = z.infer<typeof GetBrandParamsSchema>
export type UpdateBrandBodyType = z.infer<typeof UpdateBrandBodySchema>
