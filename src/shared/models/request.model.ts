import { z } from 'zod'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

export const EmptyBodySchema = z.object({}).strict()

export const PaginationQuerySchema = z.object({
	page: z.coerce.number().int().positive().default(1),
	limit: z.coerce.number().int().positive().default(10),
	search: z.string().optional(),
	sortBy: z.nativeEnum(SortBy).default(SortBy.CreatedAt),
	orderBy: z.nativeEnum(OrderBy).default(OrderBy.Desc)
})

export type EmptyBodyType = z.infer<typeof EmptyBodySchema>
export type PaginationQueryType = z.infer<typeof PaginationQuerySchema>
