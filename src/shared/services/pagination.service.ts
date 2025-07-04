import { Injectable, BadRequestException } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { BasePaginationQueryType, PaginationMetadata } from '../models/pagination.model'

export interface PaginatedResult<T> {
  data: T[]
  metadata: PaginationMetadata
}

export interface PaginationOptions {
  include?: any
  select?: any
  orderBy?: any[]
  searchableFields?: string[]
  search?: string
  cursorFields?: string[] // default: ['id']
  filters?: Record<string, any>
}

@Injectable()
export class PaginationService {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Hàm chính: phân trang chuẩn hóa, hỗ trợ offset/cursor, multi-sort, filter, search
   */
  async paginate<T>(
    modelName: string,
    query: BasePaginationQueryType,
    where: any = {},
    options: PaginationOptions = {},
  ): Promise<PaginatedResult<T>> {
    this.validateQuery(query)
    const { limit = 10, offset = 0, sortBy, sortOrder, search, cursor } = query
    const { include, select, orderBy, searchableFields, cursorFields = ['id'], filters = {} } = options

    // Build where query
    const searchQuery = search && searchableFields ? this.buildSearchQuery(search, searchableFields) : {}
    const finalWhere = { ...where, ...searchQuery, ...filters }

    // Build orderBy
    const finalOrderBy: any[] = this.buildOrderBy(orderBy, sortBy, sortOrder, cursorFields)

    // Nếu có offset (jump page)
    if (offset && offset > 0) {
      const findManyArgs: any = {
        where: finalWhere,
        orderBy: finalOrderBy,
        skip: offset,
        take: limit,
      }
      if (include) findManyArgs.include = include
      if (select) findManyArgs.select = select
      const [data, totalItems] = await this.prismaService.$transaction([
        this.prismaService[modelName].findMany(findManyArgs),
        this.prismaService[modelName].count({ where: finalWhere }),
      ])
      const metadata = this.buildMetadata({
        limit,
        offset,
        totalItems,
        sortBy,
        sortOrder,
        search,
        filters,
      })
      return { data, metadata }
    }

    // Cursor-based
    const findManyArgs: any = {
      where: finalWhere,
      orderBy: finalOrderBy,
      take: limit + 1,
    }
    // Multi-field cursor
    if (cursor) {
      findManyArgs.cursor = this.decodeCursor(cursor, cursorFields)
      findManyArgs.skip = 1
    }
    if (include) findManyArgs.include = include
    if (select) findManyArgs.select = select
    const data = await this.prismaService[modelName].findMany(findManyArgs)
    const hasNext = data.length > limit
    const result = hasNext ? data.slice(0, limit) : data
    const totalItems = await this.prismaService[modelName].count({ where: finalWhere })
    const metadata = this.buildMetadata({
      limit,
      offset: 0,
      totalItems,
      sortBy,
      sortOrder,
      search,
      filters,
      hasNext,
      hasPrevious: !!cursor,
      nextCursor: hasNext && result.length > 0 ? this.encodeCursor(result[result.length - 1], cursorFields) : null,
      prevCursor: result.length > 0 ? this.encodeCursor(result[0], cursorFields) : null,
    })
    return { data: result, metadata }
  }

  /**
   * Validate input query
   */
  private validateQuery(query: BasePaginationQueryType) {
    if (query.limit && (query.limit < 1 || query.limit > 100)) {
      throw new BadRequestException('Limit must be between 1 and 100')
    }
    if (query.offset && query.offset < 0) {
      throw new BadRequestException('Offset must be >= 0')
    }
    // Có thể validate thêm sort, cursor, ...
  }

  /**
   * Build orderBy array
   */
  private buildOrderBy(
    orderBy: any[] | undefined,
    sortBy: string | string[] | undefined,
    sortOrder: string | undefined,
    cursorFields: string[],
  ): any[] {
    if (orderBy && orderBy.length > 0) return orderBy
    if (sortBy) {
      if (Array.isArray(sortBy)) {
        return sortBy.map((field) => ({ [field]: sortOrder || 'desc' }))
      }
      return [{ [sortBy]: sortOrder || 'desc' }]
    }
    // Default: sort by cursorFields desc
    return cursorFields.map((field) => ({ [field]: 'desc' }))
  }

  /**
   * Build search query
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
   * Build metadata chuẩn hóa
   */
  private buildMetadata(params: {
    limit: number
    offset?: number
    totalItems: number
    sortBy?: string | string[]
    sortOrder?: string
    search?: string
    filters?: Record<string, any>
    hasNext?: boolean
    hasPrevious?: boolean
    nextCursor?: string | null
    prevCursor?: string | null
  }): PaginationMetadata {
    const {
      limit,
      offset = 0,
      totalItems,
      sortBy,
      sortOrder,
      search,
      filters,
      hasNext,
      hasPrevious,
      nextCursor,
      prevCursor,
    } = params
    const totalPages = Math.ceil(totalItems / limit)
    const currentPage = Math.floor(offset / limit) + 1
    return {
      limit,
      offset,
      totalItems,
      totalPages,
      currentPage,
      hasNext: typeof hasNext === 'boolean' ? hasNext : offset + limit < totalItems,
      hasPrevious: typeof hasPrevious === 'boolean' ? hasPrevious : offset > 0,
      nextCursor: nextCursor ?? null,
      prevCursor: prevCursor ?? null,
      sortBy,
      sortOrder,
      search,
      filters,
    }
  }

  /**
   * Encode multi-field cursor
   */
  private encodeCursor(row: any, cursorFields: string[]): string {
    const cursorObj: Record<string, any> = {}
    for (const field of cursorFields) {
      cursorObj[field] = row[field]
    }
    return Buffer.from(JSON.stringify(cursorObj)).toString('base64')
  }

  /**
   * Decode multi-field cursor
   */
  private decodeCursor(cursor: string, cursorFields: string[]): Record<string, any> {
    try {
      const decoded = Buffer.from(cursor, 'base64').toString()
      const obj = JSON.parse(decoded)
      const result: Record<string, any> = {}
      for (const field of cursorFields) {
        if (obj[field] === undefined) throw new BadRequestException('Invalid cursor')
        result[field] = obj[field]
      }
      return result
    } catch {
      throw new BadRequestException('Invalid cursor')
    }
  }
}
