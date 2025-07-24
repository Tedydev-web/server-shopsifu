import {
  DiscountType,
  DiscountStatus,
  DiscountApplyType,
  DisplayType,
  VoucherType
} from 'src/shared/constants/discount.constant'
import { z } from 'zod'

export const DiscountSchema = z.object({
  id: z.string(),
  name: z.string().max(500),
  description: z.string().nullable().optional(),
  discountType: z.enum([DiscountType.FIX_AMOUNT, DiscountType.PERCENTAGE]).default(DiscountType.FIX_AMOUNT),
  value: z.number().int(),
  code: z.string().max(100),
  startDate: z.coerce.date(),
  endDate: z.coerce.date(),
  maxUses: z.number().int(),
  usesCount: z.number().int().default(0),
  usersUsed: z.array(z.string()),
  maxUsesPerUser: z.number().int().default(0),
  minOrderValue: z.number().int().default(0),
  maxDiscountValue: z.number().int().nullable().optional(),
  shopId: z.string().nullable(),
  voucherType: z.enum([VoucherType.SHOP, VoucherType.PRODUCT]).default(VoucherType.SHOP),
  displayType: z.enum([DisplayType.PUBLIC, DisplayType.PRIVATE]).default(DisplayType.PUBLIC),
  isPlatform: z.boolean().default(false),
  discountStatus: z
    .enum([DiscountStatus.DRAFT, DiscountStatus.INACTIVE, DiscountStatus.ACTIVE, DiscountStatus.EXPIRED])
    .default(DiscountStatus.DRAFT),
  discountApplyType: z.enum([DiscountApplyType.ALL, DiscountApplyType.SPECIFIC]).default(DiscountApplyType.ALL),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type DiscountType = z.infer<typeof DiscountSchema>
