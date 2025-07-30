import { z } from 'zod'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'
import {
  DisplayType,
  DiscountStatus,
  DiscountType,
  DiscountApplyType,
  VoucherType
} from 'src/shared/constants/discount.constant'

export const GetDiscountsQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  name: z.string().optional(),
  code: z.string().optional(),
  discountStatus: z.enum(DiscountStatus).optional(),
  discountType: z.enum(DiscountType).optional(),
  discountApplyType: z.enum(DiscountApplyType).optional(),
  voucherType: z.enum(VoucherType).optional(),
  displayType: z.enum(DisplayType).optional(),
  isPlatform: z.preprocess((value) => value === 'true', z.boolean()).optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
  minValue: z.coerce.number().positive().optional(),
  maxValue: z.coerce.number().positive().optional(),
  shopId: z.string().optional(),
  createdById: z.string().optional(),
  orderBy: z.enum(OrderBy).default(OrderBy.Desc),
  sortBy: z.enum(SortBy).default(SortBy.CreatedAt)
})

export const GetManageDiscountsQuerySchema = GetDiscountsQuerySchema.extend({
  createdById: z.string()
})

export const GetManageDiscountsResSchema = z.object({
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
  data: DiscountSchema
})

export const CreateDiscountBodySchema = DiscountSchema.pick({
  name: true,
  description: true,
  value: true,
  code: true,
  startDate: true,
  endDate: true,
  maxUsesPerUser: true,
  minOrderValue: true,
  maxUses: true,
  maxDiscountValue: true,
  displayType: true,
  voucherType: true,
  isPlatform: true,
  discountApplyType: true,
  discountStatus: true,
  discountType: true
})
  .extend({
    brands: z.array(z.string()).optional(),
    categories: z.array(z.string()).optional(),
    products: z.array(z.string()).optional()
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.startDate >= data.endDate) {
      return ctx.addIssue({
        code: 'custom',
        path: ['endDate'],
        message: 'Ngày kết thúc phải sau ngày bắt đầu'
      })
    }

    const codeRegex = /^[A-Z0-9]{1,5}$/
    if (!codeRegex.test(data.code)) {
      return ctx.addIssue({
        code: 'custom',
        path: ['code'],
        message: 'Mã voucher chỉ được chứa chữ cái A-Z và số 0-9, tối đa 5 ký tự'
      })
    }

    if (data.discountType === 'PERCENTAGE') {
      if (data.value < 1 || data.value > 100) {
        return ctx.addIssue({
          code: 'custom',
          path: ['value'],
          message: 'Phần trăm giảm giá phải từ 1% đến 100%'
        })
      }
    }

    if (data.maxUses > 0 && data.maxUsesPerUser > data.maxUses) {
      return ctx.addIssue({
        code: 'custom',
        path: ['maxUsesPerUser'],
        message: 'Số lần sử dụng tối đa per user không được vượt quá số lần sử dụng tối đa'
      })
    }

    if (
      data.discountApplyType === 'SPECIFIC' &&
      (!data.brands || data.brands.length === 0) &&
      (!data.categories || data.categories.length === 0) &&
      (!data.products || data.products.length === 0)
    ) {
      return ctx.addIssue({
        code: 'custom',
        path: ['discountApplyType'],
        message: 'Khi chọn áp dụng cụ thể, phải chọn ít nhất một brand, category hoặc product'
      })
    }
  })

export const UpdateDiscountBodySchema = CreateDiscountBodySchema

export const CreateDiscountResSchema = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

export const UpdateDiscountResSchema = CreateDiscountResSchema

export type GetManageDiscountsQueryType = z.infer<typeof GetManageDiscountsQuerySchema>
export type GetManageDiscountsResType = z.infer<typeof GetManageDiscountsResSchema>
export type GetDiscountParamsType = z.infer<typeof GetDiscountParamsSchema>
export type GetDiscountDetailResType = z.infer<typeof GetDiscountDetailResSchema>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodySchema>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodySchema>
export type CreateDiscountResType = z.infer<typeof CreateDiscountResSchema>
export type UpdateDiscountResType = z.infer<typeof UpdateDiscountResSchema>
