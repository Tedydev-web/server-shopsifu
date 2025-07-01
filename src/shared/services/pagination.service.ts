import { Injectable } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { BasePaginationQueryType, PaginationMetadata } from '../models/core.model'

export interface PaginatedResult<T> {
  data: T[]
  metadata: PaginationMetadata
}

@Injectable()
export class PaginationService {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Tạo pagination metadata từ query và total count
   */
  createPaginationMetadata(query: BasePaginationQueryType, totalItems: number): PaginationMetadata {
    const { page, limit } = query
    const totalPages = Math.ceil(totalItems / limit)

    return {
      totalItems,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1,
    }
  }

  /**
   * Xử lý pagination cho bất kỳ model nào
   */
  async paginate<T>(
    modelName: string,
    query: BasePaginationQueryType,
    where: any = {},
    include: any = {},
    searchOptions?: {
      searchableFields?: string[]
      search?: string
    },
  ): Promise<PaginatedResult<T>> {
    const { page, limit, sortBy, sortOrder, search } = query

    // Build search query if provided
    const searchQuery =
      search && searchOptions?.searchableFields ? this.buildSearchQuery(search, searchOptions.searchableFields) : {}

    const finalWhere = { ...where, ...searchQuery }

    // Build orderBy
    const orderBy = sortBy ? { [sortBy]: sortOrder || 'desc' } : { id: 'desc' }

    const findManyArgs = {
      where: finalWhere,
      include,
      skip: (page - 1) * limit,
      take: limit,
      orderBy,
    }

    const countArgs = { where: finalWhere }

    // Execute queries
    const [data, totalItems] = await this.prismaService.$transaction([
      this.prismaService[modelName].findMany(findManyArgs),
      this.prismaService[modelName].count(countArgs),
    ])

    const metadata = this.createPaginationMetadata(query, totalItems)

    return { data, metadata }
  }

  /**
   * Xây dựng search query
   */
  private buildSearchQuery(search: string, searchableFields: string[]): any {
    if (searchableFields.length === 0) return {}

    return {
      OR: searchableFields.map((field) => ({
        [field]: { contains: search, mode: 'insensitive' },
      })),
    }
  }
}
