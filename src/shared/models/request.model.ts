import { z } from 'zod'

export const EmptyBodySchema = z.object({}).strict()

export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1), // Phải thêm coerce để chuyển từ string sang number
  limit: z.coerce.number().int().positive().default(10), // Phải thêm coerce để chuyển từ string sang number
  sortBy: z.enum(['createdAt', 'updatedAt']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
})

export type EmptyBodyType = z.infer<typeof EmptyBodySchema>
export type PaginationQueryType = z.infer<typeof PaginationQuerySchema>
