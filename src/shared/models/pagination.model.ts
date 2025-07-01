import { z } from 'zod'

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

// ==================== TYPES ====================

export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>
