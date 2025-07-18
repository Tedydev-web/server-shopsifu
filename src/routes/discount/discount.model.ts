import { z } from 'zod'
import { DiscountSchema } from 'src/shared/models/shared-discount.model'

// Schema cho params lấy chi tiết discount
export const GetDiscountParamsSchema = z
  .object({
    discountId: z.string()
  })
  .strict()

// Schema cho filter danh sách discount
export const GetDiscountsQueryType = z
  .object({
    shopId: z.string().optional(),
    status: z.string().optional(),
    now: z.coerce.date().optional()
  })
  .strict()

// Schema cho response chi tiết discount
export const GetDiscountDetailResType = z.object({
  message: z.string().optional(),
  data: DiscountSchema
})

// Schema cho response danh sách discount
export const GetDiscountsResType = z.object({
  message: z.string().optional(),
  data: z.array(DiscountSchema),
  totalItems: z.number()
})

// Schema cho tạo mới discount
export const CreateDiscountBodyType = DiscountSchema.pick({
  name: true,
  description: true,
  type: true,
  value: true,
  code: true,
  startDate: true,
  endDate: true,
  maxUsed: true,
  maxUsesPerUser: true,
  minOrderValue: true,
  appliesTo: true,
  productIds: true
}).strict()

// Schema cho cập nhật discount
export const UpdateDiscountBodyType = CreateDiscountBodyType.partial()

export type GetDiscountParamsType = z.infer<typeof GetDiscountParamsSchema>
export type GetDiscountsQueryType = z.infer<typeof GetDiscountsQueryType>
export type GetDiscountDetailResType = z.infer<typeof GetDiscountDetailResType>
export type GetDiscountsResType = z.infer<typeof GetDiscountsResType>
export type CreateDiscountBodyType = z.infer<typeof CreateDiscountBodyType>
export type UpdateDiscountBodyType = z.infer<typeof UpdateDiscountBodyType>
