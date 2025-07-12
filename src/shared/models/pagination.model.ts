import { z } from 'zod'

export const PaginationMetadataSchema = z.object({
	totalItems: z.number(),
	page: z.number(),
	limit: z.number(),
	totalPages: z.number(),
	hasNext: z.boolean(),
	hasPrev: z.boolean()
})

export const PaginationResponseSchema = <T extends z.ZodTypeAny>(
	itemSchema: T
) =>
	z.object({
		data: z.array(itemSchema),
		metadata: PaginationMetadataSchema
	})
