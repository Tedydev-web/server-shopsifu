import { z } from 'zod'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'
import {
  DiscountStatus,
  DiscountType,
  DisplayType,
  DiscountApplyType,
  VoucherType
} from 'src/shared/constants/discount.constant'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

/**
 * Dành cho client và guest
 */
export const GetDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  search: z.string().optional(),
  orderBy: z.enum([OrderBy.Asc, OrderBy.Desc]).default(OrderBy.Desc),
  sortBy: z.enum([SortBy.CreatedAt]).default(SortBy.CreatedAt)
})

/**
 * Dành cho Admin và Seller
 */
export const GetManageDiscountsQuerySchema = GetDiscountsQuerySchema.extend({
  status: z.nativeEnum(DiscountStatus).optional(),
  shopId: z.string().optional()
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

export const GetDiscountParamsSchema = z
  .object({
    discountId: z.string()
  })
  .strict()

export const GetDiscountDetailResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema.extend({
    products: z.array(z.object({ id: z.string(), name: z.string() })),
    categories: z.array(z.object({ id: z.string(), name: z.string() })),
    brands: z.array(z.object({ id: z.string(), name: z.string() }))
  })
})

export const CreateDiscountBodySchema = DiscountSchema.pick({
  name: true,
  description: true,
  discountType: true,
  value: true,
  code: true,
  startDate: true,
  endDate: true,
  maxUses: true,
  maxUsesPerUser: true,
  minOrderValue: true,
  maxDiscountValue: true,
  discountApplyType: true,
  voucherType: true,
  displayType: true,
  isPlatform: true
})
  .extend({
    productIds: z.array(z.string()).optional(),
    categoryIds: z.array(z.string()).optional(),
    brandIds: z.array(z.string()).optional()
  })
  .strict()

export const UpdateDiscountBodySchema = CreateDiscountBodySchema

export const UpdateDiscountResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

export type GetDiscountsQueryType = z.infer<typeof GetDiscountsQuerySchema>
export type GetManageDiscountsQueryType = z.infer<typeof GetManageDiscountsQuerySchema>
export type GetDiscountsResType = z.infer<typeof GetDiscountsResSchema>
export type GetDiscountParamsType = z.infer<typeof GetDiscountParamsSchema>
export type GetDiscountDetailResType = z.infer<typeof GetDiscountDetailResSchema>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodySchema>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodySchema>
export type UpdateDiscountResType = z.infer<typeof UpdateDiscountResSchema>

// Schema cho body
export const GetAvailableDiscountsBodySchema = z.object({
  cartItemIds: z.array(z.string()).min(1)
})

// Schema cho response
export const GetAvailableDiscountsResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      description: z.string().nullable(),
      discountType: z.nativeEnum(DiscountType),
      value: z.number(),
      code: z.string(),
      maxDiscountValue: z.number().nullable(),
      discountAmount: z.number().optional(),
      minOrderValue: z.number(),
      isPlatform: z.boolean().optional(),
      voucherType: z.nativeEnum(VoucherType).optional(),
      displayType: z.nativeEnum(DisplayType).optional(),
      discountApplyType: z.nativeEnum(DiscountApplyType).optional(),
      targetInfo: z.any().nullable().optional()
    })
  )
})
