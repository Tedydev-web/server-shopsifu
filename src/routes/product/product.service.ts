import { Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext } from 'nestjs-i18n'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

@Injectable()
export class ProductService {
  constructor(
    private productRepo: ProductRepo,
    private paginationService: PaginationService
  ) {}

  async list(props: { pagination: PaginationQueryType; filters: any }) {
    const languageId = I18nContext.current()?.lang as string

    // Xây dựng where clause từ filters
    const where = this.buildWhereClause(props.filters, true)

    // Xây dựng orderBy từ pagination và filters
    const orderBy = this.buildOrderBy(props.pagination, props.filters)

    return this.paginationService.paginate('product', props.pagination, {
      where,
      include: {
        productTranslations: {
          where: languageId === 'all' ? { deletedAt: null } : { deletedAt: null, languageId }
        },
        orders: {
          where: {
            deletedAt: null,
            status: 'DELIVERED'
          }
        }
      },
      orderBy,
      defaultSortField: 'createdAt'
    })
  }

  private buildWhereClause(filters: any, isPublic: boolean = true) {
    const where: any = { deletedAt: null }

    if (isPublic) {
      where.publishedAt = {
        lte: new Date(),
        not: null
      }
    }

    if (filters.search) {
      const searchTerm = filters.search
      where.name = {
        contains: searchTerm,
        mode: 'insensitive'
      }
    }

    if (filters.brandIds && filters.brandIds.length > 0) {
      const brandIds = Array.isArray(filters.brandIds) ? filters.brandIds : [filters.brandIds]
      where.brandId = {
        in: brandIds.map((id) => Number(id))
      }
    }

    if (filters.categories && filters.categories.length > 0) {
      const categories = Array.isArray(filters.categories) ? filters.categories : [filters.categories]
      where.categories = {
        some: {
          id: {
            in: categories.map((id) => Number(id))
          }
        }
      }
    }

    if (filters.minPrice !== undefined || filters.maxPrice !== undefined) {
      where.basePrice = {
        gte: filters.minPrice ? Number(filters.minPrice) : undefined,
        lte: filters.maxPrice ? Number(filters.maxPrice) : undefined
      }
    }

    if (filters.createdById) {
      where.createdById = Number(filters.createdById)
    }

    return where
  }

  private buildOrderBy(pagination: PaginationQueryType, filters: any) {
    const { sortBy = SortBy.CreatedAt, sortOrder = OrderBy.Desc } = filters

    if (sortBy === SortBy.Price) {
      return [{ basePrice: sortOrder }]
    } else if (sortBy === SortBy.Sale) {
      return [{ orders: { _count: sortOrder } }]
    }

    return [{ createdAt: sortOrder }]
  }

  async getDetail(props: { productId: number }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string,
      isPublic: true
    })
    if (!product) {
      throw NotFoundRecordException
    }
    return product
  }
}
