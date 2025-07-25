import { PaginationQuerySchema } from 'src/shared/models/request.model'
import { OrderSchema, OrderStatusSchema, ProductSKUSnapshotSchema } from 'src/shared/models/shared-order.model'
import { z } from 'zod'

export const GetOrderListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    OrderSchema.extend({
      items: z.array(ProductSKUSnapshotSchema)
    }).omit({
      receiver: true,
      deletedAt: true,
      deletedById: true,
      createdById: true,
      updatedById: true
    })
  ),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number(),
    hasNext: z.boolean(),
    hasPrev: z.boolean()
  })
})

export const GetOrderListQuerySchema = PaginationQuerySchema.extend({
  status: OrderStatusSchema.optional()
})

export const GetOrderDetailResSchema = z.object({
  message: z.string().optional(),
  data: OrderSchema.extend({
    items: z.array(ProductSKUSnapshotSchema)
  })
})

export const CreateOrderBodySchema = z
  .array(
    z.object({
      shopId: z.string(),
      receiver: z.object({
        name: z.string(),
        phone: z.string().min(9).max(20),
        address: z.string()
      }),
      cartItemIds: z.array(z.string()).min(1),
      discountCodes: z.array(z.string()).optional()
    })
  )
  .min(1)

// Thêm schema cho API calculate
export const CalculateOrderBodySchema = z.object({
  cartItemIds: z.array(z.string()).min(1),
  discountCodes: z.array(z.string()).optional()
})

export const CalculateOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    subTotal: z.number(),
    shippingFee: z.number(),
    directDiscount: z.number(),
    discounts: z.array(
      z.object({
        code: z.string(),
        name: z.string(),
        amount: z.number()
      })
    ),
    grandTotal: z.number()
  })
})

// Thêm schema cho API get available discounts
export const GetAvailableDiscountsBodySchema = z.object({
  cartItemIds: z.array(z.string()).min(1)
})

export const CreateOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    orders: z.array(OrderSchema),
    paymentId: z.string()
  })
})
export const CancelOrderBodySchema = z.object({})
export const CancelOrderResSchema = z.object({
  message: z.string().optional(),
  data: OrderSchema
})

export const GetOrderParamsSchema = z
  .object({
    orderId: z.string()
  })
  .strict()

export type GetOrderListResType = z.infer<typeof GetOrderListResSchema>
export type GetOrderListQueryType = z.infer<typeof GetOrderListQuerySchema>
export type GetOrderDetailResType = z.infer<typeof GetOrderDetailResSchema>
export type GetOrderParamsType = z.infer<typeof GetOrderParamsSchema>
export type CreateOrderBodyType = z.infer<typeof CreateOrderBodySchema>
export type CreateOrderResType = z.infer<typeof CreateOrderResSchema>
export type CancelOrderResType = z.infer<typeof CancelOrderResSchema>
export type CalculateOrderBodyType = z.infer<typeof CalculateOrderBodySchema>
export type CalculateOrderResType = z.infer<typeof CalculateOrderResSchema>
export type GetAvailableDiscountsBodyType = z.infer<typeof GetAvailableDiscountsBodySchema>
