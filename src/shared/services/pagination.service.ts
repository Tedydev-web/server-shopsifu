import { Injectable } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { PaginationQueryType, PaginationMetadata, PaginatedResult } from '../models/pagination.model'

@Injectable()
export class PaginationService {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Tạo pagination metadata từ query và total count
   */
  createPaginationMetadata(
    query: PaginationQueryType | { page?: number; limit?: number },
    totalItems: number,
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
    }
  }

  /**
   * Phân trang offset-based với sorting
   */
  async paginate<T>(
    modelName: string,
    query: PaginationQueryType | { page?: number; limit?: number; sortBy?: string; sortOrder?: 'asc' | 'desc' },
    options: {
      where?: any
      include?: any
      select?: any
      orderBy?: any[]
      defaultSortField?: string
    } = {},
  ): Promise<PaginatedResult<T>> {
    const { page = 1, limit = 10, sortBy, sortOrder = 'desc' } = query
    const { where = {}, include, select, orderBy, defaultSortField = 'id' } = options

    // Xây dựng orderBy
    const finalOrderBy = this.buildOrderBy(orderBy, sortBy, sortOrder, defaultSortField)

    // Thực hiện query với transaction để đảm bảo consistency
    const [data, totalItems] = await this.prismaService.$transaction([
      this.prismaService[modelName].findMany({
        where,
        orderBy: finalOrderBy,
        skip: (page - 1) * limit,
        take: limit,
        include,
        select,
      }),
      this.prismaService[modelName].count({ where }),
    ])

    const metadata = this.createPaginationMetadata(query, totalItems)

    return { data, metadata }
  }

  /**
   * Xây dựng orderBy clause
   */
  private buildOrderBy(
    orderBy?: any[],
    sortBy?: string,
    sortOrder: 'asc' | 'desc' = 'desc',
    defaultSortField: string = 'id',
  ): any[] {
    // Ưu tiên orderBy được truyền vào
    if (orderBy && orderBy.length > 0) {
      return orderBy
    }

    // Sử dụng sortBy nếu có
    if (sortBy) {
      return [{ [sortBy]: sortOrder }]
    }

    // Fallback về default sort field
    return [{ [defaultSortField]: sortOrder }]
  }

  /**
   * Tính toán offset từ page và limit
   */
  calculateOffset(page: number, limit: number): number {
    return (page - 1) * limit
  }

  /**
   * Validate pagination parameters
   */
  validatePaginationParams(page: number, limit: number): void {
    if (page < 1) {
      throw new Error('Page must be greater than 0')
    }
    if (limit < 1 || limit > 100) {
      throw new Error('Limit must be between 1 and 100')
    }
  }
}
