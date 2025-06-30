import { createZodDto } from 'nestjs-zod'
import { ZodType } from 'zod'
import {
  EmptyBodySchema,
  BasePaginationQuerySchema,
  BaseResponseSchema,
  SuccessResponseSchema,
  PaginatedResponseSchema,
  ErrorResponseSchema,
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
} from 'src/shared/models/core.model'

// ==================== REQUEST DTOs ====================

export class EmptyBodyDTO extends createZodDto(EmptyBodySchema) {}

// ==================== PAGINATION DTOs ====================

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}

// ==================== RESPONSE DTOs ====================

export class BaseResponseDTO extends createZodDto(BaseResponseSchema) {}
export class SuccessResponseDTO extends createZodDto(SuccessResponseSchema) {}
export class PaginatedResponseDTO extends createZodDto(PaginatedResponseSchema) {}
export class ErrorResponseDTO extends createZodDto(ErrorResponseSchema) {}

// Alias for backward compatibility
export class MessageResponseDTO extends createZodDto(BaseResponseSchema) {}

// ==================== FACTORY FUNCTIONS ====================

/**
 * Factory function để tạo typed DTO class cho success responses
 * @param dataSchema - Zod schema cho data field
 * @returns DTO class với typed data
 */
export function createTypedSuccessResponseDTO<T extends ZodType>(dataSchema: T) {
  const schema = createTypedSuccessResponseSchema(dataSchema)
  return createZodDto(schema)
}

/**
 * Factory function để tạo typed DTO class cho paginated responses
 * @param itemSchema - Zod schema cho từng item trong data array
 * @returns DTO class với typed data array
 */
export function createTypedPaginatedResponseDTO<T extends ZodType>(itemSchema: T) {
  const schema = createTypedPaginatedResponseSchema(itemSchema)
  return createZodDto(schema)
}
