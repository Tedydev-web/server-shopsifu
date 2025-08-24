import { OrderStatus } from 'src/shared/constants/order.constant'
import { z } from 'zod'
import { DiscountApplyType, DiscountType, VoucherType, DisplayType } from 'src/shared/constants/discount.constant'

export const OrderStatusSchema = z.nativeEnum(OrderStatus)

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
  paymentId: z.number(),
  orderCode: z.string().nullable(),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()]),
  // Thêm các field giá để trả về giống POST /orders/calculate
  totalItemCost: z.number().optional(),
  totalShippingFee: z.number().optional(),
  totalVoucherDiscount: z.number().optional(),
  totalPayment: z.number().optional()
})

export const ProductSKUSnapshotSchema = z.object({
  id: z.string(),
  productId: z.string().nullable(),
  productName: z.string(),
  productTranslations: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      languageId: z.string()
    })
  ),
  skuPrice: z.number(),
  image: z.string(),
  skuValue: z.string(),
  skuId: z.string().nullable(),
  orderId: z.string().nullable(),
  quantity: z.number(),
  createdAt: z.union([z.string(), z.date()])
})

/**
 * Snapshot mã giảm giá tại thời điểm áp dụng cho đơn hàng
 */
export const DiscountSnapshotSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  discountType: z.nativeEnum(DiscountType),
  value: z.number(),
  code: z.string(),
  maxDiscountValue: z.number().nullable(),
  discountAmount: z.number(),
  minOrderValue: z.number(),
  isPlatform: z.boolean(),
  voucherType: z.nativeEnum(VoucherType),
  displayType: z.nativeEnum(DisplayType),
  discountApplyType: z.nativeEnum(DiscountApplyType),
  targetInfo: z.any().nullable(), // { productIds: string[], categoryIds: string[], brandIds: string[] }
  discountId: z.string().nullable(),
  orderId: z.string().nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const OrderIncludeProductSKUSnapshotAndDiscountSchema = OrderSchema.extend({
  items: z.array(ProductSKUSnapshotSchema),
  discounts: z.array(DiscountSnapshotSchema),
  // Thêm thông tin vận chuyển tối thiểu để tính phí ship khi thanh toán online
  shipping: z
    .object({
      shippingFee: z.number().optional()
    })
    .nullable()
    .optional()
})

export type OrderType = z.infer<typeof OrderSchema>
export type OrderIncludeProductSKUSnapshotAndDiscountType = z.infer<
  typeof OrderIncludeProductSKUSnapshotAndDiscountSchema
>
export type DiscountSnapshotType = z.infer<typeof DiscountSnapshotSchema>
