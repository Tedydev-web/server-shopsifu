import { DiscountType, DiscountStatus, DiscountApplyType } from 'src/shared/constants/discount.constant'
import { z } from 'zod'
import { ProductSchema } from 'src/shared/models/shared-product.model'
import { CategorySchema } from './shared-category.model'
import { BrandSchema } from './shared-brand.model'

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
  usesCount: z.number().int().default(0),
  usersUsed: z.array(z.string()),
  maxUsesPerUser: z.number().int().default(0),
  minOrderValue: z.number().int().default(0),
  maxDiscountValue: z.number().int().nullable().optional(),
  canSaveBeforeStart: z.boolean().default(false),
  isPublic: z.boolean().default(true),
  shopId: z.string().nullable(),
  status: z.enum([DiscountStatus.DRAFT, DiscountStatus.INACTIVE, DiscountStatus.ACTIVE, DiscountStatus.EXPIRED]),
  appliesTo: z.nativeEnum(DiscountApplyType).default(DiscountApplyType.ALL),
  products: z.lazy(() => z.array(ProductSchema).optional()),
  categories: z.lazy(() => z.array(CategorySchema).optional()),
  brands: z.lazy(() => z.array(BrandSchema).optional()),
  createdById: z.string().nullable(),
  updatedById: z.string().nullable(),
  deletedById: z.string().nullable(),
  deletedAt: z.date().nullable(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type DiscountType = z.infer<typeof DiscountSchema>
