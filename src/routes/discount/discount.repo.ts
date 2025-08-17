import { Injectable } from '@nestjs/common'
import {
  GetManageDiscountsResType,
  GetDiscountDetailResType,
  CreateDiscountBodyType,
  UpdateDiscountBodyType,
  GetAvailableDiscountsQueryType
} from './discount.model'
import { DiscountType } from 'src/shared/models/shared-discount.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'

// Types cho admin list query
type AdminListQuery = {
  limit: number
  page: number
  name?: string
  code?: string
  discountStatus?: string
  discountType?: string
  discountApplyType?: string
  voucherType?: string
  displayType?: string
  isPlatform?: boolean
  startDate?: Date
  endDate?: Date
  minValue?: number
  maxValue?: number
  shopId?: string
  createdById?: string
  orderBy: string
  sortBy: string
}

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Lấy danh sách discounts khả dụng cho checkout (không phân trang)
   */
  async getAvailableDiscounts({
    limit,
    cartItemIds,
    onlyShopDiscounts,
    onlyPlatformDiscounts
  }: GetAvailableDiscountsQueryType): Promise<DiscountType[]> {
    try {
      console.log('Getting available discounts with params:', {
        limit,
        cartItemIds,
        onlyShopDiscounts,
        onlyPlatformDiscounts
      })

      const where = await this.buildAvailableDiscountsWhereClause({
        cartItemIds,
        onlyShopDiscounts,
        onlyPlatformDiscounts
      })

      console.log('Built where clause:', where)

      const data = await this.prismaService.discount.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        include: this.getDiscountIncludeClause()
      })

      console.log('Found discounts:', data.length)

      const filteredData = await this.filterAvailableDiscounts(data, cartItemIds)
      console.log('Filtered discounts:', filteredData.length)

      return filteredData
    } catch (error) {
      console.error('Error in getAvailableDiscounts:', error)
      throw error
    }
  }

  /**
   * Lấy danh sách discount cho admin management (có phân trang)
   */
  async list(query: AdminListQuery): Promise<GetManageDiscountsResType> {
    const { limit, page, ...filters } = query
    const skip = (page - 1) * limit

    const where = this.buildAdminListWhereClause(filters)
    const orderBy = this.buildOrderByClause(query.orderBy, query.sortBy)

    const [totalItems, data] = await Promise.all([
      this.prismaService.discount.count({ where }),
      this.prismaService.discount.findMany({
        where,
        orderBy,
        skip,
        take: limit
      })
    ])

    return {
      data,
      metadata: this.buildPaginationMetadata(totalItems, page, limit)
    }
  }

  /**
   * Tìm discount theo ID
   */
  findById(discountId: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findUnique({
      where: {
        id: discountId,
        deletedAt: null
      }
    })
  }

  /**
   * Lấy chi tiết discount cho admin
   */
  async getDetail({
    discountId,
    createdById
  }: {
    discountId: string
    createdById: string
  }): Promise<GetDiscountDetailResType | null> {
    return this.prismaService.discount
      .findUnique({
        where: {
          id: discountId,
          deletedAt: null,
          createdById
        }
      })
      .then((discount) => (discount ? { data: discount } : null))
  }

  /**
   * Tạo discount mới
   */
  async create({
    createdById,
    data
  }: {
    createdById: string
    data: CreateDiscountBodyType
  }): Promise<GetDiscountDetailResType> {
    const { brands, categories, products, ...discountData } = data

    return this.prismaService.discount
      .create({
        data: {
          createdById,
          ...discountData,
          voucherType: discountData.voucherType as any,
          ...this.buildRelationsClause({ brands, categories, products })
        }
      })
      .then((discount) => ({ data: discount }))
  }

  /**
   * Cập nhật discount
   */
  async update({
    id,
    updatedById,
    data
  }: {
    id: string
    updatedById: string
    data: UpdateDiscountBodyType
  }): Promise<DiscountType> {
    const { brands, categories, products, ...discountData } = data

    return this.prismaService.discount.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...discountData,
        voucherType: discountData.voucherType as any,
        updatedById,
        ...this.buildRelationsClause({ brands, categories, products }, 'set')
      }
    })
  }

  /**
   * Xóa discount (soft delete hoặc hard delete)
   */
  async delete(
    {
      id,
      deletedById
    }: {
      id: string
      deletedById: string
    },
    isHard?: boolean
  ): Promise<DiscountType> {
    if (isHard) {
      return this.prismaService.discount.delete({
        where: { id }
      })
    }

    return this.prismaService.discount.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        deletedAt: new Date(),
        deletedById
      }
    })
  }

  /**
   * Tìm discount theo code
   */
  findByCode(code: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findUnique({
      where: {
        code,
        deletedAt: null
      },
      include: this.getDiscountIncludeClause()
    })
  }

  // Helper methods

  /**
   * Build where clause cho available discounts
   */
  private async buildAvailableDiscountsWhereClause({
    cartItemIds,
    onlyShopDiscounts,
    onlyPlatformDiscounts
  }: {
    cartItemIds?: string[]
    onlyShopDiscounts?: boolean
    onlyPlatformDiscounts?: boolean
  }): Promise<Prisma.DiscountWhereInput> {
    const where: Prisma.DiscountWhereInput = {
      deletedAt: null,
      discountStatus: 'ACTIVE'
    }

    // Filter theo thời gian hiện tại
    const now = new Date()
    where.startDate = { lte: now }
    where.endDate = { gte: now }

    // Tính toán orderTotal và shopId từ cartItemIds
    const { orderTotal, shopId } = await this.calculateOrderInfoFromCartItems(cartItemIds)

    // Filter theo shop discounts hoặc platform discounts
    if (onlyShopDiscounts) {
      where.isPlatform = false
      // Nếu có shopId, chỉ lấy discounts của shop đó hoặc discounts không có shopId (global shop discounts)
      if (shopId) {
        where.OR = [{ shopId: shopId }, { shopId: null }]
      }
    } else if (onlyPlatformDiscounts) {
      where.isPlatform = true
    }

    // Filter theo min order value nếu có
    if (orderTotal && orderTotal > 0) {
      where.OR = [{ minOrderValue: 0 }, { minOrderValue: { lte: orderTotal } }]
    }

    return where
  }

  /**
   * Build where clause cho admin list
   */
  private buildAdminListWhereClause(
    filters: Omit<AdminListQuery, 'limit' | 'page' | 'orderBy' | 'sortBy'>
  ): Prisma.DiscountWhereInput {
    const where: Prisma.DiscountWhereInput = {
      deletedAt: null
    }

    if (filters.createdById) {
      where.createdById = filters.createdById
    }

    if (filters.name) {
      where.name = { contains: filters.name, mode: 'insensitive' }
    }

    if (filters.code) {
      where.code = { contains: filters.code, mode: 'insensitive' }
    }

    if (filters.discountStatus) {
      where.discountStatus = filters.discountStatus as any
    }

    if (filters.discountType) {
      where.discountType = filters.discountType as any
    }

    if (filters.discountApplyType) {
      where.discountApplyType = filters.discountApplyType as any
    }

    if (filters.voucherType) {
      where.voucherType = filters.voucherType as any
    }

    if (filters.displayType) {
      where.displayType = filters.displayType as any
    }

    if (filters.isPlatform !== undefined) {
      where.isPlatform = filters.isPlatform
    }

    if (filters.startDate) {
      where.startDate = { gte: filters.startDate }
    }

    if (filters.endDate) {
      where.endDate = { lte: filters.endDate }
    }

    if (filters.minValue !== undefined || filters.maxValue !== undefined) {
      where.value = {
        gte: filters.minValue,
        lte: filters.maxValue
      }
    }

    if (filters.shopId) {
      where.shopId = filters.shopId
    }

    return where
  }

  /**
   * Build orderBy clause
   */
  private buildOrderByClause(orderBy: string, sortBy: string): Prisma.DiscountOrderByWithRelationInput {
    if (sortBy === 'value') {
      return { value: orderBy as any }
    }

    if (sortBy === 'usesCount') {
      return { usesCount: orderBy as any }
    }

    return { createdAt: orderBy as any }
  }

  /**
   * Build pagination metadata
   */
  private buildPaginationMetadata(totalItems: number, page: number, limit: number) {
    const totalPages = Math.ceil(totalItems / limit)
    return {
      totalItems,
      page,
      limit,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  }

  /**
   * Build relations clause cho create/update
   */
  private buildRelationsClause(
    relations: { brands?: string[]; categories?: string[]; products?: string[] },
    operation: 'connect' | 'set' = 'connect'
  ) {
    const result: any = {}

    if (relations.brands) {
      result.brands = {
        [operation]: relations.brands.map((id) => ({ id }))
      }
    }

    if (relations.categories) {
      result.categories = {
        [operation]: relations.categories.map((id) => ({ id }))
      }
    }

    if (relations.products) {
      result.products = {
        [operation]: relations.products.map((id) => ({ id }))
      }
    }

    return result
  }

  /**
   * Get include clause cho discount queries
   */
  private getDiscountIncludeClause() {
    return {
      products: { select: { id: true } },
      categories: { select: { id: true } },
      brands: { select: { id: true } }
    }
  }

  /**
   * Filter available discounts theo logic phức tạp (đã validate đầy đủ)
   */
  private async filterAvailableDiscounts(discounts: DiscountType[], cartItemIds?: string[]): Promise<DiscountType[]> {
    if (!cartItemIds || cartItemIds.length === 0) {
      return discounts.filter((discount) => {
        // Kiểm tra số lần sử dụng
        if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
          return false
        }
        return true
      })
    }

    // Lấy thông tin cart items để validate
    const { productIds, categoryIds, brandIds } = await this.calculateOrderInfoFromCartItems(cartItemIds)

    return discounts.filter((discount) => {
      // Kiểm tra số lần sử dụng
      if (discount.maxUses > 0 && discount.usesCount >= discount.maxUses) {
        return false
      }

      // Kiểm tra discountApplyType SPECIFIC
      if (discount.discountApplyType === 'SPECIFIC') {
        const discountWithRelations = discount as any

        const hasValidProduct = productIds.some((productId) =>
          discountWithRelations.products?.some((p: any) => p.id === productId)
        )
        const hasValidCategory = categoryIds.some((categoryId) =>
          discountWithRelations.categories?.some((c: any) => c.id === categoryId)
        )
        const hasValidBrand = brandIds.some((brandId) =>
          discountWithRelations.brands?.some((b: any) => b.id === brandId)
        )

        if (!hasValidProduct && !hasValidCategory && !hasValidBrand) {
          return false
        }
      }

      return true
    })
  }

  /**
   * Tính toán orderTotal và shopId từ cartItemIds
   */
  private async calculateOrderInfoFromCartItems(
    cartItemIds?: string[]
  ): Promise<{ orderTotal: number; shopId?: string; productIds: string[]; categoryIds: string[]; brandIds: string[] }> {
    if (!cartItemIds || cartItemIds.length === 0) {
      return { orderTotal: 0, productIds: [], categoryIds: [], brandIds: [] }
    }

    try {
      console.log('Calculating order info for cartItemIds:', cartItemIds)

      const cartItems = await this.prismaService.cartItem.findMany({
        where: { id: { in: cartItemIds } },
        include: {
          sku: {
            include: {
              product: {
                include: {
                  createdBy: true,
                  categories: true,
                  brand: true
                }
              }
            }
          }
        }
      })

      console.log('Found cartItems:', cartItems.length)

      if (cartItems.length === 0) {
        console.log('No cart items found')
        return { orderTotal: 0, productIds: [], categoryIds: [], brandIds: [] }
      }

      // Tính toán orderTotal
      const orderTotal = cartItems.reduce((total, item) => {
        return total + item.quantity * item.sku.price
      }, 0)

      // Lấy shopId từ cart item đầu tiên (shop = createdBy của product)
      const shopId = cartItems[0]?.sku?.product?.createdBy?.id

      // Lấy productIds, categoryIds, brandIds
      const productIds = [...new Set(cartItems.map((item) => item.sku.product.id))]
      const categoryIds = [...new Set(cartItems.flatMap((item) => item.sku.product.categories.map((cat) => cat.id)))]
      const brandIds = [...new Set(cartItems.map((item) => item.sku.product.brand?.id).filter(Boolean))]

      console.log('Calculated order info:', { orderTotal, shopId, productIds, categoryIds, brandIds })

      return { orderTotal, shopId, productIds, categoryIds, brandIds }
    } catch (error) {
      console.error('Error calculating order info from cart items:', error)
      return { orderTotal: 0, productIds: [], categoryIds: [], brandIds: [] }
    }
  }
}
