/* eslint-disable prefer-const */
export interface PaginatedResult<T> {
	data: T[]
	metadata: {
		totalItems: number
		page: number
		limit: number
		totalPages: number
		hasNext: boolean
		hasPrev: boolean
	}
}

export interface PaginationArgs {
	page: number
	limit: number
	search?: string
	sortBy?: string
	orderBy?: 'asc' | 'desc'
}

interface Model {
	count: (args?: any) => Promise<number>
	findMany: (args?: any) => Promise<any[]>
}

export async function paginate<T>(
	model: Model,
	pagination: PaginationArgs,
	args?: Parameters<Model['findMany']>[0],
	searchableFields?: string[]
): Promise<PaginatedResult<T>> {
	const { page, limit, search, sortBy, orderBy } = pagination
	const skip = (page - 1) * limit
	const take = limit

	const where = args?.where ? { ...args.where } : {}

	if (search && searchableFields && searchableFields.length > 0) {
		where.OR = searchableFields.map(field => ({
			[field]: {
				contains: search,
				mode: 'insensitive'
			}
		}))
	}

	const countArgs = { where }

	const [totalItems, data] = await Promise.all([
		model.count(countArgs),
		model.findMany({
			...args,
			where,
			skip,
			take,
			orderBy: sortBy ? { [sortBy]: orderBy } : args?.orderBy
		})
	])

	const totalPages = Math.ceil(totalItems / limit)
	const hasNext = page < totalPages
	const hasPrev = page > 1

	return {
		data,
		metadata: {
			totalItems,
			page,
			limit,
			totalPages,
			hasNext,
			hasPrev
		}
	}
}
