import { createZodDto } from 'nestjs-zod'
import { z, ZodType } from 'zod'

export const BasePaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(10),
  sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
  sortBy: z.string().optional(), // Added sortBy for client-side configuration
  search: z.string().optional(),
  includeDeleted: z.coerce.boolean().optional().default(false) // Added includeDeleted
})

export const PaginatedResponseSchema = z.object({
  data: z.array(z.any()),
  metadata: z.object({
    totalItems: z.number(),
    page: z.number(),
    limit: z.number(),
    totalPages: z.number()
  })
})

export const createPaginatedResponseSchema = <T extends z.ZodType>(itemSchema: T) =>
  PaginatedResponseSchema.extend({
    data: z.array(itemSchema)
  })

export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>

export interface PaginationMetadata {
  totalItems: number
  page: number
  limit: number
  totalPages: number
}

export interface PaginatedResponseType<T> {
  data: T[]
  metadata: PaginationMetadata
}

export function createPaginatedResponse<T>(
  data: T[],
  totalItems: number,
  options: BasePaginationQueryType // Updated to use BasePaginationQueryType
): PaginatedResponseType<T> {
  const { page = 1, limit = 10 } = options
  // Tạo object theo thứ tự chính xác
  const orderedResult: any = {}
  // Data trước
  orderedResult.data = data
  // Metadata sau
  orderedResult.metadata = {
    totalItems,
    page,
    limit,
    totalPages: Math.ceil(totalItems / limit)
  }
  return orderedResult
}

export class BasePaginationQueryDTO extends createZodDto(BasePaginationQuerySchema) {}

export function createPaginatedResponseDTO<T extends ZodType>(itemSchema: T) {
  return class extends createZodDto(createPaginatedResponseSchema(itemSchema)) {}
}
