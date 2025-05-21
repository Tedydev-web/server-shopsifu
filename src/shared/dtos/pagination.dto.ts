import { createZodDto } from 'nestjs-zod'
import { ZodType } from 'zod'
import {
  BasePaginationQuerySchema,
  PaginatedResponseSchema,
  createPaginatedResponseSchema
} from '../models/pagination.model'

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}

export class PaginatedResponseDTO extends createZodDto(PaginatedResponseSchema) {}

export function createPaginatedResponseDTO<T extends ZodType>(itemSchema: T) {
  return class extends createZodDto(createPaginatedResponseSchema(itemSchema)) {}
}
