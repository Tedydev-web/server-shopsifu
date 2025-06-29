import { z } from 'zod'

// Base response schema for all success responses
export const BaseResponseSchema = z.object({
  success: z.literal(true),
  statusCode: z.number().int().positive(),
  message: z.string(),
})

// Success response with optional data
export const SuccessResponseSchema = BaseResponseSchema.extend({
  data: z.any().optional().nullable(),
  metadata: z.record(z.any()).optional(),
})

// Message-only response (no data field)
export const MessageResSchema = BaseResponseSchema

// Paginated response schema
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

// Error response schema
export const ErrorResponseSchema = z.object({
  success: z.literal(false),
  statusCode: z.number().int().positive(),
  code: z.string(),
  message: z.string(),
  details: z.any().optional().nullable(),
  timestamp: z.string().datetime(),
  path: z.string(),
})

// Helper function to create typed success response schema
export const createTypedSuccessResponseSchema = <T extends z.ZodType>(dataSchema: T) =>
  BaseResponseSchema.extend({
    data: dataSchema,
    metadata: z.record(z.any()).optional(),
  })

// Helper function to create typed paginated response schema
export const createTypedPaginatedResponseSchema = <T extends z.ZodType>(itemSchema: T) =>
  BaseResponseSchema.extend({
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

// Type definitions
export type BaseResponseType = z.infer<typeof BaseResponseSchema>
export type SuccessResponseType<T = any> = z.infer<typeof SuccessResponseSchema> & { data?: T }
export type MessageResType = z.infer<typeof MessageResSchema>
export type PaginatedResponseType<T = any> = z.infer<typeof PaginatedResponseSchema> & { data: T[] }
export type ErrorResponseType = z.infer<typeof ErrorResponseSchema>
