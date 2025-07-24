import { z } from 'zod'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'
import { DiscountStatus, DiscountType } from 'src/shared/constants/discount.constant'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'
import { VoucherType } from 'src/shared/constants/discount.constant'

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
    brandIds: z.array(z.string()).optional(),
    // Thêm trường để validate radio giới hạn mức giảm tối đa
    hasMaxDiscountLimit: z.boolean().optional()
  })
  .strict()
  .superRefine((data, ctx) => {
    // Validate ngày kết thúc phải sau ngày bắt đầu
    if (data.endDate && data.startDate && new Date(data.endDate) <= new Date(data.startDate)) {
      ctx.addIssue({
        code: 'custom',
        path: ['endDate'],
        message: 'Ngày kết thúc phải sau ngày bắt đầu'
      })
    }
    // Validate voucherType
    if (data.voucherType === VoucherType.SHOP && data.productIds && data.productIds.length > 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['productIds'],
        message: 'Voucher toàn shop không được chọn sản phẩm cụ thể'
      })
    }
    if (data.voucherType === VoucherType.PRODUCT && (!data.productIds || data.productIds.length === 0)) {
      ctx.addIssue({
        code: 'custom',
        path: ['productIds'],
        message: 'Voucher sản phẩm phải chọn ít nhất 1 sản phẩm'
      })
    }
    // Validate maxDiscountValue
    if (data.discountType === DiscountType.PERCENTAGE) {
      if (data.hasMaxDiscountLimit && (data.maxDiscountValue === null || data.maxDiscountValue === undefined)) {
        ctx.addIssue({
          code: 'custom',
          path: ['maxDiscountValue'],
          message: 'Phải nhập mức giảm tối đa khi chọn giới hạn'
        })
      }
      if (!data.hasMaxDiscountLimit && data.maxDiscountValue) {
        ctx.addIssue({
          code: 'custom',
          path: ['maxDiscountValue'],
          message: 'Không nhập mức giảm tối đa khi không giới hạn'
        })
      }
    }
    if (data.discountType === DiscountType.FIX_AMOUNT && data.maxDiscountValue) {
      ctx.addIssue({
        code: 'custom',
        path: ['maxDiscountValue'],
        message: 'Không nhập mức giảm tối đa cho loại giảm giá theo số tiền'
      })
    }
  })

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
      description: z.string().nullable().optional(),
      type: z.string(),
      value: z.number(),
      code: z.string(),
      maxDiscountValue: z.number().nullable().optional(),
      minOrderValue: z.number(),
      appliesTo: z.string()
    })
  )
})
