import { Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { PaginatedResponseType, BasePaginationQueryType } from 'src/shared/models/pagination.model'
import { PrismaService } from '../services/prisma.service'

export type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

// Search options for performance optimization
export interface SearchOptions {
  useFullTextSearch?: boolean
  searchableFields?: string[]
  relationSearches?: Record<string, string[]>
}

export abstract class BaseRepository<T> {
  protected readonly modelName: string
  protected readonly logger = new Logger(BaseRepository.name)

  constructor(
    protected readonly prismaService: PrismaService,
    modelName: string,
  ) {
    this.modelName = modelName
  }

  protected getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  async findById(id: string | number, prismaClient?: PrismaTransactionClient): Promise<T | null> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].findUnique({ where: { id } })
  }

  async create(data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].create({ data })
  }

  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].update({ where: { id }, data })
  }

  async delete(id: string | number, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].delete({ where: { id } })
  }

  async findMany(options: { where?: any; include?: any } = {}, prismaClient?: PrismaTransactionClient): Promise<T[]> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].findMany(options)
  }

  // --- Standard Offset-based Pagination (Primary & Only) ---
  // Best for: Admin panels, reports, web applications, standard CRUD operations
  protected async paginate(
    query: BasePaginationQueryType,
    where: any = {},
    include: any = {},
    prismaClient?: PrismaTransactionClient,
    searchOptions?: SearchOptions,
  ): Promise<PaginatedResponseType<T>> {
    const client = this.getClient(prismaClient)
    const { page, limit, sortBy, sortOrder, search } = query

    const searchQuery = search ? this.buildSearchQuery(search, searchOptions) : {}
    const finalWhere = { ...where, ...searchQuery }

    // Validate sortBy
    const sortableFields = this.getSortableFields()
    let orderBy: any
    if (!sortBy) {
      orderBy = { id: 'desc' } // Default sort
    } else if (sortableFields.includes(sortBy)) {
      orderBy = { [sortBy]: sortOrder || 'desc' }
    } else {
      // Nếu sortBy không hợp lệ, throw lỗi chuẩn hóa
      throw new Error(`Trường sortBy không hợp lệ: ${sortBy}. Chỉ hỗ trợ: ${sortableFields.join(', ')}`)
    }

    const findManyArgs = {
      where: finalWhere,
      include,
      skip: (page - 1) * limit,
      take: limit,
      orderBy,
    }

    const countArgs = { where: finalWhere }

    let items: T[]
    let totalItems: number

    if (prismaClient) {
      ;[items, totalItems] = await Promise.all([
        client[this.modelName].findMany(findManyArgs),
        client[this.modelName].count(countArgs),
      ])
    } else {
      ;[items, totalItems] = await this.prismaService.$transaction([
        this.prismaService[this.modelName].findMany(findManyArgs),
        this.prismaService[this.modelName].count(countArgs),
      ])
    }

    const totalPages = Math.ceil(totalItems / limit)

    return {
      data: items,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1,
      },
    }
  }

  // --- Helper Methods ---
  private buildSearchQuery(search: string, options?: SearchOptions): any {
    const searchableFields = options?.searchableFields || this.getSearchableFields()
    if (searchableFields.length === 0) return {}
    if (options?.useFullTextSearch) {
      return this.buildFullTextSearchQuery(search, searchableFields)
    }
    return {
      OR: searchableFields.map((field) => ({
        [field]: { contains: search, mode: 'insensitive' },
      })),
    }
  }

  private buildFullTextSearchQuery(search: string, fields: string[]): any {
    // Có thể customize cho DB engine
    return {
      OR: fields.map((field) => ({
        [field]: { search },
      })),
    }
  }

  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể tìm kiếm.
   */
  protected abstract getSearchableFields(): string[]
  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể sort.
   */
  protected abstract getSortableFields(): string[]

  // --- Performance Optimization Methods ---
  protected async getEstimatedCount(where: any = {}): Promise<number> {
    // Sử dụng EXPLAIN ESTIMATE cho large tables thay vì COUNT(*)
    // Implementation tùy thuộc vào database engine
    try {
      return await this.prismaService[this.modelName].count({ where })
    } catch (error) {
      this.logger.warn(`Failed to get count, returning estimate: ${error}`)
      return 0
    }
  }

  protected generateCacheKey(prefix: string, params: any): string {
    const key = Object.keys(params)
      .sort()
      .map((k) => `${k}:${params[k]}`)
      .join('|')
    return `${prefix}:${Buffer.from(key).toString('base64')}`
  }
}
