import { createZodDto } from 'nestjs-zod'
import { ZodType } from 'zod'
import {
  MessageResSchema,
  SuccessResponseSchema,
  PaginatedResponseSchema,
  ErrorResponseSchema,
  createTypedSuccessResponseSchema,
  createTypedPaginatedResponseSchema,
} from 'src/shared/models/response.model'

// Base DTOs
export class MessageResDTO extends createZodDto(MessageResSchema) {}
export class SuccessResponseDTO extends createZodDto(SuccessResponseSchema) {}
export class PaginatedResponseDTO extends createZodDto(PaginatedResponseSchema) {}
export class ErrorResponseDTO extends createZodDto(ErrorResponseSchema) {}

// Factory function to create a typed DTO class for success responses.
export function createTypedSuccessResponseDTO<T extends ZodType>(dataSchema: T) {
  const schema = createTypedSuccessResponseSchema(dataSchema)
  return createZodDto(schema)
}

// Factory function to create a typed DTO class for paginated responses.
export function createTypedPaginatedResponseDTO<T extends ZodType>(itemSchema: T) {
  const schema = createTypedPaginatedResponseSchema(itemSchema)
  return createZodDto(schema)
}
