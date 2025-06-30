import { z, ZodType } from 'zod'

// ==================== REQUEST SCHEMAS ====================

export const EmptyBodySchema = z.object({}).strict()

// ==================== PAGINATION SCHEMAS ====================

export const BasePaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().min(1).max(100).optional().default(10),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  sortBy: z.string().optional(),
  search: z.string().optional(),
})

export interface PaginationMetadata {
  totalItems: number
  page: number
  limit: number
  totalPages: number
  hasNext: boolean
  hasPrev: boolean
}

// ==================== RESPONSE SCHEMAS ====================

export const BaseResponseSchema = z.object({
  success: z.literal(true),
  statusCode: z.number().int().positive(),
  message: z.string(),
})

export const SuccessResponseSchema = BaseResponseSchema.extend({
  data: z.any(),
})

export const PaginatedResponseSchema = BaseResponseSchema.extend({
  data: z.array(z.any()),
  metadata: z.object({
    totalItems: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    limit: z.number().int().positive(),
    totalPages: z.number().int().nonnegative(),
    hasNext: z.boolean(),
    hasPrev: z.boolean(),
  }),
})

export const ErrorResponseSchema = z.object({
  success: z.literal(false),
  statusCode: z.number().int().positive(),
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.any().optional(),
  }),
  requestId: z.string().optional(),
})

// ==================== FACTORY FUNCTIONS ====================

export function createTypedSuccessResponseSchema<T extends ZodType>(dataSchema: T) {
  return BaseResponseSchema.extend({
    data: dataSchema,
  })
}

export function createTypedPaginatedResponseSchema<T extends ZodType>(itemSchema: T) {
  return BaseResponseSchema.extend({
    data: z.array(itemSchema),
    metadata: z.object({
      totalItems: z.number().int().nonnegative(),
      page: z.number().int().positive(),
      limit: z.number().int().positive(),
      totalPages: z.number().int().nonnegative(),
      hasNext: z.boolean(),
      hasPrev: z.boolean(),
    }),
  })
}

// ==================== TYPES ====================

// Request Types
export type EmptyBodyType = z.infer<typeof EmptyBodySchema>

// Pagination Types
export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>

// Response Types
export type BaseResponseType = z.infer<typeof BaseResponseSchema>
export type SuccessResponseType<T = any> = BaseResponseType & { data: T }
export type ErrorResponseType = z.infer<typeof ErrorResponseSchema>

// Paginated Response Type - Consistent với base repository
export interface PaginatedResponseType<T> {
  success: true
  statusCode: number
  message: string
  data: T[]
  metadata: PaginationMetadata
}

// Message Response Type - Cho các response chỉ có message
export type MessageResponseType = BaseResponseType
