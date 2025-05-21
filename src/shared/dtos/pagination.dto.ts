import { createZodDto } from 'nestjs-zod'
import { ZodType } from 'zod'
import {
  BasePaginationQuerySchema,
  PaginatedResponseSchema,
  createPaginatedResponseSchema
} from '../models/pagination.model'

// DTO cơ bản cho query parameters phân trang
export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}

// DTO cơ bản cho response phân trang
export class PaginatedResponseDTO extends createZodDto(PaginatedResponseSchema) {}

// Helper function để tạo DTO cho response phân trang với schema cụ thể
export function createPaginatedResponseDTO<T extends ZodType>(itemSchema: T) {
  return class extends createZodDto(createPaginatedResponseSchema(itemSchema)) {}
}
