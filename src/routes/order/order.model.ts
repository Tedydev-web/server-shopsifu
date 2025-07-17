import { PaginationQuerySchema } from 'src/shared/models/request.model'
import { OrderSchema, OrderStatusSchema } from 'src/shared/models/shared-order.model'
import { z } from 'zod'

export const ProductSKUSnapshotSchema = z.object({
  id: z.string(),
  productId: z.string().nullable(),
  productName: z.string(),
  productTranslations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      description: z.string(),
      languageId: z.string()
    })
  ),
  skuPrice: z.number(),
  image: z.string(),
  skuValue: z.string(),
  skuId: z.string().nullable(),
  orderId: z.string().nullable(),
  quantity: z.number(),

  createdAt: z.date()
})

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

export const GetOrderDetailResSchema = OrderSchema.extend({
  message: z.string().optional(),
  items: z.array(ProductSKUSnapshotSchema)
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
      cartItemIds: z.array(z.string()).min(1)
    })
  )
  .min(1)

export const CreateOrderResSchema = z.object({
  message: z.string().optional(),
  orders: z.array(OrderSchema),
  paymentId: z.string()
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
