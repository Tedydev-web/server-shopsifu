import { DiscountType, DiscountStatus, DiscountApplyType } from 'src/shared/constants/discount.constant'
import { z } from 'zod'

/**
 * Schema cho entity Discount mapping với Prisma model
 */
export const DiscountSchema = z.object({
  id: z.string(),
  name: z.string().max(500),
  description: z.string().max(1000),
  type: z.enum([DiscountType.FIX_AMOUNT, DiscountType.PERCENTAGE]),
  value: z.number().int(),
  code: z.string().max(100),
  startDate: z.coerce.date(),
  endDate: z.coerce.date(),
  maxUses: z.number().int(),
  usesCount: z.number().int(),
  usersUsed: z.array(z.string()),
  maxUsesPerUser: z.number().int(),
  minOrderValue: z.number().int(),
  canSaveBeforeStart: z.boolean().default(false),
  isPublic: z.boolean().default(true),
  shopId: z.string().nullable(),
  status: z.enum([DiscountStatus.DRAFT, DiscountStatus.INACTIVE, DiscountStatus.ACTIVE, DiscountStatus.EXPIRED]),
  appliesTo: z.enum([DiscountApplyType.ALL, DiscountApplyType.SPECIFIC]),
  products: z.array(z.string()).optional(),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type DiscountTypeSchema = z.infer<typeof DiscountSchema>
