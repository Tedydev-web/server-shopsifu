import { z } from 'zod'
import {
  DiscountApplyType,
  DiscountStatus,
  DiscountType,
  DisplayType,
  VoucherType
} from '../constants/discount.constant'

export const DiscountSnapshotSchema = z.object({
  id: z.string(),
  name: z.string().trim().max(500),
  description: z.string().nullable(),
  value: z.number().int().min(0),
  code: z.string().trim().max(100),
  maxDiscountValue: z.number().int().min(0).nullable(),
  discountAmount: z.number().int().min(0),
  minOrderValue: z.number().int().min(0),
  targetInfo: z.record(z.string(), z.any()).nullable(),
  discountId: z.string().nullable(),
  orderId: z.string().nullable(),
  discountApplyType: z.nativeEnum(DiscountApplyType),
  discountType: z.nativeEnum(DiscountType),
  displayType: z.nativeEnum(DisplayType),
  isPlatform: z.boolean(),
  voucherType: z.nativeEnum(VoucherType),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export const DiscountSchema = z.object({
  id: z.string(),
  name: z.string().trim().max(500),
  description: z.string().nullable(),
  value: z.number().int().min(0),
  code: z.string().trim().max(100),
  startDate: z.coerce.date(),
  endDate: z.coerce.date(),
  usesCount: z.number().int().min(0).default(0),
  usersUsed: z.array(z.string()).default([]),
  maxUsesPerUser: z.number().int().min(0).default(0),
  minOrderValue: z.number().int().min(0).default(0),
  maxUses: z.number().int().min(0).default(0),
  shopId: z.string().nullable(),
  maxDiscountValue: z.number().int().min(0).nullable(),
  displayType: z.nativeEnum(DisplayType).default('PUBLIC'),
  voucherType: z.nativeEnum(VoucherType).default('SHOP'),
  isPlatform: z.boolean().default(false),
  discountApplyType: z.nativeEnum(DiscountApplyType).default('ALL'),
  discountStatus: z.nativeEnum(DiscountStatus).default('DRAFT'),
  discountType: z.nativeEnum(DiscountType).default('FIX_AMOUNT'),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.union([z.string(), z.date()]).nullable(),
  createdAt: z.union([z.string(), z.date()]),
  updatedAt: z.union([z.string(), z.date()])
})

export type DiscountType = z.infer<typeof DiscountSchema>
