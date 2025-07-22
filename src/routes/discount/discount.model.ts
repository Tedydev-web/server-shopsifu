import { z } from 'zod'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'
import { DiscountStatus } from 'src/shared/constants/discount.constant'

// Query cho public/client: GET /discounts/available
export const GetAvailableDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  shopId: z.string().nullable().optional(),
  isPublic: z.boolean().default(true),
  status: z.string().optional(),
  search: z.string().optional(),
  orderValue: z.coerce.number().int().min(0).default(0)
})

// Response cho GET /discounts/available
const AvailableDiscountSchema = DiscountSchema.extend({
  discountAmount: z.number(),
  isBestChoice: z.boolean().optional()
})
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

// Body & response cho POST /discounts/verify
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

// Params & response cho GET /discounts/:discountId
export const GetDiscountParamsSchema = z
  .object({
    discountId: z.string()
  })
  .strict()
export const GetDiscountDetailResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

// Query cho manage (admin/seller): GET /manage-discount/discounts
export const GetManageDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  shopId: z.string().nullable().optional(),
  isPublic: z.boolean().optional(),
  status: z.nativeEnum(DiscountStatus).optional(),
  search: z.string().optional()
})
// Response cho manage list
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

// Body cho create/update
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
  maxDiscountValue: true
})
  .extend({
    shopId: z.string().nullable().optional(),
    products: z.array(z.string()).optional(),
    categories: z.array(z.string()).optional(),
    brands: z.array(z.string()).optional()
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
    if (data.type === 'FIX_AMOUNT' && data.maxDiscountValue) {
      ctx.addIssue({
        code: 'custom',
        path: ['maxDiscountValue'],
        message: 'Mức giảm tối đa chỉ áp dụng cho loại voucher phần trăm.'
      })
    }
  })
export const UpdateDiscountBodySchema = CreateDiscountBodySchema.innerType().partial()

// Export type cho controller/service dùng
export type GetAvailableDiscountsQueryType = z.infer<typeof GetAvailableDiscountsQuerySchema>
export type GetAvailableDiscountsResType = z.infer<typeof GetAvailableDiscountsResSchema>
export type VerifyDiscountBodyType = z.infer<typeof VerifyDiscountBodySchema>
export type VerifyDiscountResType = z.infer<typeof VerifyDiscountResSchema>
export type GetDiscountParamsType = z.infer<typeof GetDiscountParamsSchema>
export type GetDiscountDetailResType = z.infer<typeof GetDiscountDetailResSchema>
export type GetManageDiscountsQueryType = z.infer<typeof GetManageDiscountsQuerySchema>
export type GetDiscountsResType = z.infer<typeof GetDiscountsResSchema>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodySchema>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodySchema>
