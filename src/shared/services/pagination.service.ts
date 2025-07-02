import { Injectable } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { BasePaginationQueryType, PaginationMetadata } from '../models/pagination.model'

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
  createPaginationMetadata(
    query: BasePaginationQueryType,
    totalItems: number,
    extra?: Partial<PaginationMetadata>,
  ): PaginationMetadata {
    const { page = 1, limit = 10 } = query
    const totalPages = Math.ceil(totalItems / limit)
    return {
      totalItems,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrevious: page > 1,
      ...extra,
    }
  }

  /**
   * Phân trang hỗn hợp: page-based hoặc cursor-based (infinite scroll)
   */
  async paginate<T>(
    modelName: string,
    query: BasePaginationQueryType,
    where: any = {},
    options: {
      include?: any
      select?: any
      orderBy?: any[]
      searchableFields?: string[]
      search?: string
      cursorField?: string // default: 'id'
    } = {},
  ): Promise<PaginatedResult<T>> {
    const { page = 1, limit = 10, sortBy, sortOrder, search, cursor } = query
    const { include, select, orderBy, searchableFields, cursorField = 'id' } = options

    // Build search query if provided
    const searchQuery = search && searchableFields ? this.buildSearchQuery(search, searchableFields) : {}
    const finalWhere = { ...where, ...searchQuery }

    // Multi-field sort
    let finalOrderBy: any[] = []
    if (orderBy && orderBy.length > 0) {
      finalOrderBy = orderBy
    } else if (sortBy) {
      if (Array.isArray(sortBy)) {
        finalOrderBy = sortBy.map((field) => ({ [field]: sortOrder || 'desc' }))
      } else {
        finalOrderBy = [{ [sortBy]: sortOrder || 'desc' }]
      }
    } else {
      finalOrderBy = [{ [cursorField]: 'desc' }]
    }

    // Cursor-based (infinite scroll)
    if (cursor) {
      const findManyArgs: any = {
        where: finalWhere,
        orderBy: finalOrderBy,
        take: limit + 1, // lấy dư 1 để xác định hasNext
        cursor: { [cursorField]: this.parseCursor(cursor) },
        skip: 1, // bỏ qua cursor hiện tại
      }
      if (include) findManyArgs.include = include
      if (select) findManyArgs.select = select
      const data = await this.prismaService[modelName].findMany(findManyArgs)
      const hasNext = data.length > limit
      const result = hasNext ? data.slice(0, limit) : data
      const nextCursor = hasNext ? this.encodeCursor(result[result.length - 1][cursorField]) : null
      const prevCursor = result.length > 0 ? this.encodeCursor(result[0][cursorField]) : null
      // Không cần totalItems cho infinite scroll
      return {
        data: result,
        metadata: {
          totalItems: 0,
          page: 1,
          limit,
          totalPages: 1,
          hasNext,
          hasPrevious: false,
          nextCursor,
          prevCursor,
        },
      }
    }

    // Page-based
    const findManyArgs: any = {
      where: finalWhere,
      orderBy: finalOrderBy,
      skip: (page - 1) * limit,
      take: limit,
    }
    if (include) findManyArgs.include = include
    if (select) findManyArgs.select = select
    const [data, totalItems] = await this.prismaService.$transaction([
      this.prismaService[modelName].findMany(findManyArgs),
      this.prismaService[modelName].count({ where: finalWhere }),
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

  /**
   * Encode/decode cursor (có thể mở rộng cho nhiều trường)
   */
  private encodeCursor(value: any): string {
    return Buffer.from(String(value)).toString('base64')
  }
  private parseCursor(cursor: string): any {
    return Buffer.from(cursor, 'base64').toString()
  }
}
