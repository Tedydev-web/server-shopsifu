import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

const CoreSuccessSchema = z.object({
  success: z.literal(true), // Removed .default(true)
  statusCode: z.number().int().positive(),
  message: z.string()
})

export const BaseSuccessResponseSchema = CoreSuccessSchema.extend({
  data: z.any().optional().nullable()
})

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

export const MessageResSchema = CoreSuccessSchema

export const createTypedSuccessResponseSchema = <T extends z.ZodType>(dataSchema: T) => {
  return z.object({
    ...CoreSuccessSchema.shape,
    data: dataSchema
  })
}

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

export function createTypedSuccessResponseDto<T extends z.ZodType>(dataSchema: T): any {
  return createZodDto(createTypedSuccessResponseSchema(dataSchema)) as any
}

export function createDataPaginatedResponseDto<T extends z.ZodType>(itemSchema: T): any {
  return createZodDto(createDataPaginatedResponseSchema(itemSchema)) as any
}

export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class ErrorResponseDto extends createZodDto(ErrorResponseSchema) {}
