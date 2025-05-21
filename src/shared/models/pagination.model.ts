import { z } from 'zod'

// Base Schema cho query parameters phân trang
export const BasePaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(10),
  sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
  search: z.string().optional()
})

// Schema cho response phân trang
export const PaginatedResponseSchema = z.object({
  data: z.array(z.any()),
  totalItems: z.number(),
  page: z.number(),
  limit: z.number(),
  totalPages: z.number()
})

// Type generic cho response phân trang với schema cụ thể
export const createPaginatedResponseSchema = <T extends z.ZodType>(itemSchema: T) =>
  PaginatedResponseSchema.extend({
    data: z.array(itemSchema)
  })

// Types
export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>

export interface PaginationOptions extends BasePaginationQueryType {
  sortBy?: string
  includeDeleted?: boolean
}

export interface PaginatedResponseType<T> {
  data: T[]
  totalItems: number
  page: number
  limit: number
  totalPages: number
}

// Factory function để tạo response phân trang
export function createPaginatedResponse<T>(
  data: T[],
  totalItems: number,
  options: PaginationOptions
): PaginatedResponseType<T> {
  const { page = 1, limit = 10 } = options
  return {
    data,
    totalItems,
    page,
    limit,
    totalPages: Math.ceil(totalItems / limit)
  }
}
