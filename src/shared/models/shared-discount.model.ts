import { z } from 'zod'
import { DiscountApplyType, DiscountStatus, DiscountType } from '../constants/discount.constant'

export const DiscountSchema = z.object({
  id: z.string(),
  name: z.string().max(500),
  description: z.string().max(1000),
  type: z.enum([DiscountType.FIX_AMOUNT, DiscountType.PERCENTAGE]),
  value: z.number().int(),
  code: z.string().max(100),
  startDate: z.date(),
  endDate: z.date(),
  maxUsed: z.number().int(),
  usesCount: z.number().int(),
  usersUsed: z.array(z.string()),
  maxUsesPerUser: z.number().int(),
  minOrderValue: z.number().int(),
  shopId: z.string(),
  status: z.enum([DiscountStatus.DRAFT, DiscountStatus.INACTIVE, DiscountStatus.ACTIVE, DiscountStatus.EXPIRED]),
  appliesTo: z.enum([DiscountApplyType.ALL, DiscountApplyType.SPECIFIC]),
  productIds: z.array(z.string()),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type DiscountTypeEnum = keyof typeof DiscountType
export type DiscountStatusEnum = keyof typeof DiscountStatus
export type DiscountApplyTypeEnum = keyof typeof DiscountApplyType
export type DiscountSchemaType = z.infer<typeof DiscountSchema>
