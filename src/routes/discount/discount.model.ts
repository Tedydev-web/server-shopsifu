import { z } from 'zod'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

// Schemas for public/client-facing endpoints
export const GetDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  shopId: z.string().nullable().optional(),
  isPublic: z.boolean().default(true),
  status: z.string().optional(),
  search: z.string().optional(),
  orderValue: z.coerce.number().int().min(0).default(0) // Thêm orderValue
})

export const GetDiscountsResSchema = z.object({
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

const AvailableDiscountSchema = DiscountSchema
const UnavailableDiscountSchema = AvailableDiscountSchema.extend({
  reason: z.string()
})

export const GetAvailableDiscountsResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    available: z.array(AvailableDiscountSchema),
    unavailable: z.array(UnavailableDiscountSchema)
  })
})

// Schemas for admin/seller-facing endpoints
export const GetManageDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  shopId: z.string().nullable().optional(),
  isPublic: z.boolean().optional(),
  status: z.nativeEnum(DiscountStatus).optional(),
  search: z.string().optional()
})

export const GetDiscountParamsSchema = z
  .object({
    discountId: z.string()
  })
  .strict()

export const GetDiscountDetailResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
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
  status: true,
  appliesTo: true,
  products: true
})
  .extend({
    shopId: z.string().nullable().optional()
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.appliesTo === 'SPECIFIC' && (!data.products || data.products.length === 0)) {
      ctx.addIssue({
        code: 'custom',
        path: ['products'],
        message: 'Phải chọn ít nhất 1 sản phẩm khi áp dụng cho sản phẩm cụ thể.'
      })
    }
  })

export const UpdateDiscountBodySchema = CreateDiscountBodySchema.innerType().partial()

export const UpdateDiscountResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

export const VerifyDiscountBodySchema = z.object({
  code: z.string(),
  orderValue: z.number().int(),
  cart: z
    .array(z.object({ shopId: z.string(), productId: z.string(), quantity: z.number(), price: z.number() }))
    .optional()
})

export const VerifyDiscountResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    discountAmount: z.number(),
    discount: DiscountSchema.pick({
      code: true,
      type: true,
      value: true,
      shopId: true,
      appliesTo: true
    })
  })
})

// Exporting all types
export type GetDiscountsQueryType = z.infer<typeof GetDiscountsQuerySchema>
export type GetManageDiscountsQueryType = z.infer<typeof GetManageDiscountsQuerySchema>
export type GetDiscountsResType = z.infer<typeof GetDiscountsResSchema>
export type GetAvailableDiscountsResType = z.infer<typeof GetAvailableDiscountsResSchema>
export type GetDiscountParamsType = z.infer<typeof GetDiscountParamsSchema>
export type GetDiscountDetailResType = z.infer<typeof GetDiscountDetailResSchema>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodySchema>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodySchema>
export type UpdateDiscountResType = z.infer<typeof UpdateDiscountResSchema>
export type VerifyDiscountBodyType = z.infer<typeof VerifyDiscountBodySchema>
export type VerifyDiscountResType = z.infer<typeof VerifyDiscountResSchema>
