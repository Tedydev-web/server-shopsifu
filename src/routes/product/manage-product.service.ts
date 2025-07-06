import { ForbiddenException, Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { CreateProductBodyType, UpdateProductBodyType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RoleName } from 'src/shared/constants/role.constant'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class ManageProductService {
  constructor(
    private productRepo: ProductRepo,
    private paginationService: PaginationService,
    private i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Kiểm tra nếu người dùng không phải là người tạo sản phẩm hoặc admin thì không cho tiếp tục
   */
  validatePrivilege({
    userIdRequest,
    roleNameRequest,
    createdById
  }: {
    userIdRequest: number
    roleNameRequest: string
    createdById: number | undefined | null
  }) {
    if (userIdRequest !== createdById && roleNameRequest !== RoleName.Admin) {
      throw new ForbiddenException()
    }
    return true
  }

  /**
   * @description: Xem danh sách sản phẩm của một shop, bắt buộc phải truyền query param là `createdById`
   */
  async list(props: { pagination: PaginationQueryType; filters: any; userIdRequest: number; roleNameRequest: string }) {
    this.validatePrivilege({
      userIdRequest: props.userIdRequest,
      roleNameRequest: props.roleNameRequest,
      createdById: props.filters.createdById
    })

    const languageId = I18nContext.current()?.lang as string

    // Xây dựng where clause từ filters
    const where = this.buildWhereClause(props.filters, false)

    // Xây dựng orderBy từ pagination và filters
    const orderBy = this.buildOrderBy(props.pagination, props.filters)

    const result = await this.paginationService.paginate('product', props.pagination, {
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

    return {
      ...result,
      message: this.i18n.t('product.product.success.GET_PRODUCTS')
    }
  }

  private buildWhereClause(filters: any, isPublic: boolean = false) {
    const where: any = { deletedAt: null }

    if (isPublic) {
      where.publishedAt = {
        lte: new Date(),
        not: null
      }
    } else if (filters.isPublic === true) {
      where.publishedAt = {
        lte: new Date(),
        not: null
      }
    } else if (filters.isPublic === false) {
      where.OR = [{ publishedAt: null }, { publishedAt: { gt: new Date() } }]
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

  async getDetail(props: { productId: number; userIdRequest: number; roleNameRequest: string }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string
    })

    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: props.userIdRequest,
      roleNameRequest: props.roleNameRequest,
      createdById: product.createdById
    })

    return {
      data: product,
      message: this.i18n.t('product.product.success.GET_PRODUCT_DETAIL')
    }
  }

  async create({ data, createdById }: { data: CreateProductBodyType; createdById: number }) {
    const product = await this.productRepo.create({
      createdById,
      data
    })

    return {
      data: product,
      message: this.i18n.t('product.product.success.CREATE_SUCCESS')
    }
  }

  async update({
    productId,
    data,
    updatedById,
    roleNameRequest
  }: {
    productId: number
    data: UpdateProductBodyType
    updatedById: number
    roleNameRequest: string
  }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: updatedById,
      roleNameRequest,
      createdById: product.createdById
    })
    try {
      const updatedProduct = await this.productRepo.update({
        id: productId,
        updatedById,
        data
      })

      return {
        data: updatedProduct,
        message: this.i18n.t('product.product.success.UPDATE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({
    productId,
    deletedById,
    roleNameRequest
  }: {
    productId: number
    deletedById: number
    roleNameRequest: string
  }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: deletedById,
      roleNameRequest,
      createdById: product.createdById
    })
    try {
      await this.productRepo.delete({
        id: productId,
        deletedById
      })
      return {
        message: this.i18n.t('product.product.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
