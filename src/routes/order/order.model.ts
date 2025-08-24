import { PaginationQuerySchema } from 'src/shared/models/request.model'
import {
  OrderSchema,
  OrderStatusSchema,
  ProductSKUSnapshotSchema,
  DiscountSnapshotSchema
} from 'src/shared/models/shared-order.model'
import { z } from 'zod'

export const GetOrderListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    OrderSchema.extend({
      items: z.array(ProductSKUSnapshotSchema),
      discounts: z.array(DiscountSnapshotSchema).optional(),
      orderCode: z.string().nullable().optional(),
      totalItemCost: z.number(),
      totalShippingFee: z.number(),
      totalVoucherDiscount: z.number(),
      totalPayment: z.number()
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

export const GetManageOrderListResSchema = z.object({
  message: z.string().optional(),
  data: z.array(
    OrderSchema.extend({
      items: z.array(ProductSKUSnapshotSchema),
      discounts: z.array(DiscountSnapshotSchema).optional(),
      orderCode: z.string().nullable().optional(),

      totalItemCost: z.number().optional().default(0),
      totalShippingFee: z.number().optional().default(0),
      totalVoucherDiscount: z.number().optional().default(0),
      totalPayment: z.number().optional().default(0)
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

export const GetManageOrderListQuerySchema = PaginationQuerySchema.extend({
  status: OrderStatusSchema.optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  customerName: z.string().optional(),
  orderCode: z.string().optional()
})

export const GetOrderListQuerySchema = PaginationQuerySchema.extend({
  status: OrderStatusSchema.optional()
})

export const GetOrderDetailResSchema = z.object({
  message: z.string().optional(),
  data: OrderSchema.extend({
    items: z.array(ProductSKUSnapshotSchema),
    orderCode: z.string().nullable().optional()
  })
})

export const GetManageOrderDetailResSchema = z.object({
  message: z.string().optional(),
  data: OrderSchema.extend({
    items: z.array(ProductSKUSnapshotSchema),
    orderCode: z.string().nullable().optional()
  })
})

export const CreateOrderBodySchema = z.object({
  shops: z
    .array(
      z.object({
        shopId: z.string(),
        receiver: z.object({
          name: z.string(),
          phone: z.string().min(9).max(20),
          address: z.string(),
          provinceId: z.number().int().positive().optional(),
          districtId: z.number().int().positive().optional(),
          wardCode: z.string().optional()
        }),
        cartItemIds: z.array(z.string()).min(1),
        discountCodes: z.array(z.string()).optional(),
        shippingInfo: z
          .object({
            service_id: z.number().optional(),
            service_type_id: z.number().optional(),

            config_fee_id: z.string().optional(),
            extra_cost_id: z.string().optional(),
            weight: z.number().positive(),
            length: z.number().positive(),
            width: z.number().positive(),
            height: z.number().positive(),
            shippingFee: z.number().nonnegative().default(0),
            payment_type_id: z.number().optional(),
            note: z.string().optional(),
            required_note: z.string().optional(),
            coupon: z.string().nullable().optional(),
            pick_shift: z.array(z.number()).optional()
          })
          .optional()
          .refine((v) => !v || typeof v.service_id === 'number' || typeof v.service_type_id === 'number', {
            message: 'shipping.error.MISSING_SERVICE_IDENTIFIER'
          }),
        isCod: z.boolean().optional()
      })
    )
    .min(1),
  platformDiscountCodes: z.array(z.string()).optional()
})

export const CalculateOrderPerShopSchema = z.object({
  shops: z
    .array(
      z.object({
        shopId: z.string(),
        cartItemIds: z.array(z.string()).min(1),
        shippingFee: z.number().nonnegative().default(0),
        discountCodes: z.array(z.string()).optional()
      })
    )
    .min(1),
  platformDiscountCodes: z.array(z.string()).optional()
})

export const CalculateOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    totalItemCost: z.number(),
    totalShippingFee: z.number(),
    totalVoucherDiscount: z.number(),
    totalPayment: z.number(),
    shops: z
      .array(
        z.object({
          shopId: z.string(),
          itemCost: z.number(),
          shippingFee: z.number(),
          voucherDiscount: z.number(),
          platformVoucherDiscount: z.number().optional(),
          itemCount: z.number().optional(),
          payment: z.number()
        })
      )
      .optional()
  })
})

export const CreateOrderResSchema = z.object({
  message: z.string().optional(),
  data: z.object({
    orders: z.array(
      OrderSchema.extend({
        orderCode: z.string().nullable().optional()
      })
    ),
    paymentId: z.number()
  })
})

export const CancelOrderResSchema = z.object({
  message: z.string().optional(),
  data: OrderSchema.extend({
    orderCode: z.string().nullable().optional()
  })
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
export type CalculateOrderResType = z.infer<typeof CalculateOrderResSchema>
export type CalculateOrderPerShopType = z.infer<typeof CalculateOrderPerShopSchema>
export type GetManageOrderListQueryType = z.infer<typeof GetManageOrderListQuerySchema>
export type GetManageOrderListResType = z.infer<typeof GetManageOrderListResSchema>
export type GetManageOrderDetailResType = z.infer<typeof GetManageOrderDetailResSchema>
