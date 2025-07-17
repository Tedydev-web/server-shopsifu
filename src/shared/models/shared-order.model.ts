import { OrderStatus } from 'src/shared/constants/order.constant'
import { z } from 'zod'

export const OrderStatusSchema = z.enum([
  OrderStatus.PENDING_PAYMENT,
  OrderStatus.PENDING_PICKUP,
  OrderStatus.PENDING_DELIVERY,
  OrderStatus.DELIVERED,
  OrderStatus.RETURNED,
  OrderStatus.CANCELLED
])

export const OrderSchema = z.object({
  id: z.string(),
  userId: z.string(),
  status: OrderStatusSchema,
  receiver: z.object({
    name: z.string(),
    phone: z.string(),
    address: z.string()
  }),
  shopId: z.string().nullable(),
  paymentId: z.string(),

  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

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

export const OrderIncludeProductSKUSnapshotSchema = OrderSchema.extend({
  items: z.array(ProductSKUSnapshotSchema)
})

export type OrderType = z.infer<typeof OrderSchema>
export type OrderIncludeProductSKUSnapshotType = z.infer<typeof OrderIncludeProductSKUSnapshotSchema>
