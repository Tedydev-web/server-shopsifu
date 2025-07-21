import { z } from 'zod'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

export const DiscountParamsSchema = z
  .object({
    discountId: z.string()
  })
  .strict()

export const DiscountDetailResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

export const DiscountListQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  shopId: z.string().optional(),
  isPublic: z.boolean().optional(),
  status: z.string().optional(),
  search: z.string().optional()
})

export const DiscountListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(DiscountSchema),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const CreateDiscountBodySchema = DiscountSchema.pick({
  name: true,
  description: true,
  type: true,
  value: true,
  code: true,
  startDate: true,
  endDate: true,
  maxUses: true,
  maxUsesPerUser: true,
  minOrderValue: true,
  canSaveBeforeStart: true,
  isPublic: true,
  shopId: true,
  status: true,
  appliesTo: true
}).strict()

export const UpdateDiscountBodySchema = CreateDiscountBodySchema.partial()

export const VerifyDiscountBodySchema = z.object({
  code: z.string(),
  userId: z.string(),
  orderValue: z.number().int(),
  productIds: z.array(z.string()).optional()
})

export type DiscountParamsType = z.infer<typeof DiscountParamsSchema>
export type DiscountDetailResType = z.infer<typeof DiscountDetailResSchema>
export type DiscountListQueryType = z.infer<typeof DiscountListQuerySchema>
export type DiscountListResType = z.infer<typeof DiscountListResSchema>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodySchema>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodySchema>
export type VerifyDiscountBodyType = z.infer<typeof VerifyDiscountBodySchema>
