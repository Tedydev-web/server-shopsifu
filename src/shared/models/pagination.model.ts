import { z } from 'zod'

// ==================== PAGINATION SCHEMAS ====================

export const BasePaginationQuerySchema = z.object({
  limit: z.coerce.number().int().positive().min(1).max(100).optional().default(10),
  offset: z.coerce.number().int().min(0).optional().default(0),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
  sortBy: z.string().optional(),
  search: z.string().optional(),
  cursor: z.string().optional(), // for cursor-based pagination
})

export const PaginationMetadataSchema = z.object({
  limit: z.number(),
  offset: z.number().optional(),
  hasNext: z.boolean(),
  hasPrevious: z.boolean(),
  nextCursor: z.string().nullish(),
  prevCursor: z.string().nullish(),
  totalItems: z.number().optional(),
  totalPages: z.number().optional(),
  currentPage: z.number().optional(),
  sortBy: z.union([z.string(), z.array(z.string())]).optional(),
  sortOrder: z.string().optional(),
  search: z.string().optional(),
  filters: z.record(z.any()).optional(),
})

export interface PaginationMetadata {
  limit: number
  offset?: number
  hasNext: boolean
  hasPrevious: boolean
  nextCursor?: string | null
  prevCursor?: string | null
  totalItems?: number
  totalPages?: number
  currentPage?: number
  sortBy?: string | string[]
  sortOrder?: string
  search?: string
  filters?: Record<string, any>
}

// ==================== TYPES ====================

export type BasePaginationQueryType = z.infer<typeof BasePaginationQuerySchema>
