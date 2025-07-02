import { z } from 'zod'

// ==================== PAGINATION SCHEMAS ====================

export const BasePaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().min(1).max(100).optional().default(10),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  sortBy: z.union([z.string(), z.array(z.string())]).optional(),
  search: z.string().optional(),
  cursor: z.string().optional(), // for infinite scroll
})

export interface PaginationMetadata {
  totalItems: number
  page: number
  limit: number
  totalPages: number
  hasNext: boolean
  hasPrevious: boolean
  nextCursor?: string | null
  prevCursor?: string | null
}

// ==================== TYPES ====================

export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>
