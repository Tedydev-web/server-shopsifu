import { Injectable } from '@nestjs/common'
import { CreateOrderBodyType, GetOrderListQueryType } from 'src/routes/order/order.model'
import { OrderRepo } from 'src/routes/order/order.repo'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

@Injectable()
export class OrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly paginationService: PaginationService
  ) {}

  async list(userId: number, query: GetOrderListQueryType) {
    // Xây dựng where clause từ filters
    const where = this.buildWhereClause(userId, query)

    // Xây dựng orderBy từ pagination và filters
    const orderBy = this.buildOrderBy(query, query)

    return this.paginationService.paginate('order', query, {
      where,
      include: {
        items: true
      },
      orderBy,
      defaultSortField: 'createdAt'
    })
  }

  private buildWhereClause(userId: number, filters: any) {
    const where: any = {
      userId,
      deletedAt: null
    }

    // Filter theo status
    if (filters.status) {
      where.status = filters.status
    }

    // Filter theo shopId
    if (filters.shopId) {
      where.shopId = Number(filters.shopId)
    }

    // Search theo receiver name, phone, address
    if (filters.search) {
      const searchTerm = filters.search
      where.OR = [
        {
          receiver: {
            path: ['name'],
            string_contains: searchTerm
          }
        },
        {
          receiver: {
            path: ['phone'],
            string_contains: searchTerm
          }
        },
        {
          receiver: {
            path: ['address'],
            string_contains: searchTerm
          }
        }
      ]
    }

    return where
  }

  private buildOrderBy(pagination: PaginationQueryType, filters: any) {
    const { sortBy = SortBy.CreatedAt, sortOrder = OrderBy.Desc } = filters

    if (sortBy === SortBy.CreatedAt) {
      return [{ createdAt: sortOrder }]
    } else if (sortBy === SortBy.Status) {
      return [{ status: sortOrder }]
    }

    return [{ createdAt: sortOrder }]
  }

  async create(userId: number, body: CreateOrderBodyType) {
    return this.orderRepo.create(userId, body)
  }

  cancel(userId: number, orderId: number) {
    return this.orderRepo.cancel(userId, orderId)
  }

  detail(userId: number, orderId: number) {
    return this.orderRepo.detail(userId, orderId)
  }
}
