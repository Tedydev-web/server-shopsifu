import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

/**
 * Core schema for any successful response, containing common fields.
 */
const CoreSuccessSchema = z.object({
  success: z.literal(true), // Removed .default(true)
  statusCode: z.number().int().positive(),
  message: z.string()
})

/**
 * Schema for a basic success response, potentially with untyped data.
 * Extends CoreSuccessSchema.
 */
export const BaseSuccessResponseSchema = CoreSuccessSchema.extend({
  data: z.any().optional().nullable()
})

/**
 * Schema for a basic paginated response, potentially with untyped data items.
 * Extends CoreSuccessSchema and adds pagination metadata.
 */
export const BasePaginatedResponseSchema = CoreSuccessSchema.extend({
  data: z.array(z.any()).optional().nullable(),
  metadata: z // metadata is now required
    .object({
      totalItems: z.number().int(),
      page: z.number().int(),
      limit: z.number().int(),
      totalPages: z.number().int()
    })
})

/**
 * Schema for a response that only contains a message.
 * This is identical to CoreSuccessSchema.
 */
export const MessageResSchema = CoreSuccessSchema

/**
 * Factory function to create a schema for a success response with a specific data type.
 * Extends CoreSuccessSchema.
 */
export const createTypedSuccessResponseSchema = <T extends z.ZodType>(dataSchema: T) => {
  return z.object({
    ...CoreSuccessSchema.shape,
    data: dataSchema
  })
}

/**
 * Factory function to create a schema for a paginated response with a specific item type for the data array.
 * Extends CoreSuccessSchema and adds typed data and metadata.
 */
const paginatedMetadataSchema = z.object({
  totalItems: z.number().int(),
  page: z.number().int(),
  limit: z.number().int(),
  totalPages: z.number().int() // Removed trailing comma
})

export const createDataPaginatedResponseSchema = <T extends z.ZodType>(itemSchema: T) => {
  return z.object({
    ...CoreSuccessSchema.shape,
    data: z.array(itemSchema), // data is an array (can be empty)
    metadata: paginatedMetadataSchema // metadata is now based on the non-optional local schema
  })
}

export const ErrorResponseSchema = z.object({
  success: z.literal(false), // Removed .default(false)
  statusCode: z.number().int(),
  error: z.string(), // Mã lỗi máy có thể đọc (machine-readable error code)
  message: z.string(), // Thông báo lỗi cho người dùng (human-readable, đã được dịch)
  details: z.any().optional().nullable() // Chi tiết lỗi (ví dụ: lỗi validation)
})

// DTO for a generic success response (data is any or not present)
export class BaseSuccessResponseDto extends createZodDto(BaseSuccessResponseSchema) {}

// DTO for a generic paginated response (data is any[] or not present)
export class BasePaginatedResponseDto extends createZodDto(BasePaginatedResponseSchema) {}

/**
 * Factory function to create a DTO for a success response with strongly-typed data.
 */
export function createTypedSuccessResponseDto<T extends z.ZodType>(dataSchema: T): any {
  return createZodDto(createTypedSuccessResponseSchema(dataSchema)) as any
}

/**
 * Factory function to create a DTO for a paginated response with strongly-typed data items.
 */
export function createDataPaginatedResponseDto<T extends z.ZodType>(itemSchema: T): any {
  return createZodDto(createDataPaginatedResponseSchema(itemSchema)) as any
}

export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class ErrorResponseDto extends createZodDto(ErrorResponseSchema) {}
