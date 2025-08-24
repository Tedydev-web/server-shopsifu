import { z } from 'zod'
import { OrderStatus } from 'src/shared/constants/order.constant'

// Query parameters cho list orders
export const GetManageOrderListQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().default(10),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  customerName: z.string().optional(),
  orderCode: z.string().optional(),
  status: z.nativeEnum(OrderStatus).optional()
})

// Response cho list orders
export const GetManageOrderListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    z.object({
      id: z.string(),
      userId: z.string(),
      status: z.nativeEnum(OrderStatus),
      shopId: z.string(),
      paymentId: z.number(),
      createdAt: z.string(),
      updatedAt: z.string(),
      items: z.array(z.any()),
      user: z.object({
        id: z.string(),
        name: z.string(),
        email: z.string(),
        phoneNumber: z.string().nullable()
      })
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

// Response cho order detail
export const GetManageOrderDetailResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    id: z.string(),
    userId: z.string(),
    status: z.nativeEnum(OrderStatus),
    receiver: z.object({
      name: z.string(),
      phone: z.string(),
      address: z.string()
    }),
    shopId: z.string(),
    paymentId: z.number(),
    createdById: z.string(),
    updatedById: z.string().nullable(),
    deletedById: z.string().nullable(),
    deletedAt: z.string().nullable(),
    createdAt: z.string(),
    updatedAt: z.string(),
    items: z.array(z.any()),
    totalItemCost: z.number(),
    totalShippingFee: z.number(),
    totalVoucherDiscount: z.number(),
    totalPayment: z.number(),
    user: z.object({
      id: z.string(),
      name: z.string(),
      email: z.string(),
      phoneNumber: z.string().nullable()
    })
  })
})

// Schema cho update chỉ status (PATCH)
export const UpdateOrderStatusSchema = z.object({
  status: z.nativeEnum(OrderStatus),
  note: z.string().optional()
})

import { OrderStatusType } from 'src/shared/constants/order.constant'

// Types
export type GetManageOrderListQueryType = z.infer<typeof GetManageOrderListQuerySchema>
export type GetManageOrderListResType = z.infer<typeof GetManageOrderListResSchema>
export type GetManageOrderDetailResType = z.infer<typeof GetManageOrderDetailResSchema>
export type UpdateOrderStatusType = z.infer<typeof UpdateOrderStatusSchema>
