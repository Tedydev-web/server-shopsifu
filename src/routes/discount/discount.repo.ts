import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { GetManageDiscountsQueryType, CreateDiscountBodyType, UpdateDiscountBodyType } from './discount.model'
import { DiscountType } from 'src/shared/models/shared-discount.model'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Danh sách discount (có phân trang, filter)
   */
  async list(query: GetManageDiscountsQueryType): Promise<{ data: DiscountType[]; metadata: any }> {
    const { page = 1, limit = 10, shopId, isPublic, status, search } = query
    const where: any = { deletedAt: null }
    if (shopId === null) {
      where.shopId = null
    } else if (shopId) {
      where.shopId = shopId
    }
    if (typeof isPublic === 'boolean') where.isPublic = isPublic
    if (status) where.status = status
    if (search) where.name = { contains: search, mode: 'insensitive' }
    const skip = (page - 1) * limit
    const [totalItems, data] = await Promise.all([
      this.prismaService.discount.count({ where }),
      this.prismaService.discount.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          products: true,
          categories: true,
          brands: true
        }
      })
    ])
    const totalPages = Math.ceil(totalItems / limit)
    return {
      data,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    }
  }

  /**
   * Tạo mới discount
   */
  async create({ createdById, data }: { createdById: string; data: CreateDiscountBodyType }): Promise<DiscountType> {
    const { products, categories, brands, ...discountData } = data
    return this.prismaService.discount.create({
      data: {
        ...discountData,
        createdById,
        products: products && products.length > 0 ? { connect: products.map((id) => ({ id })) } : undefined,
        categories: categories && categories.length > 0 ? { connect: categories.map((id) => ({ id })) } : undefined,
        brands: brands && brands.length > 0 ? { connect: brands.map((id) => ({ id })) } : undefined
      },
      include: {
        products: true,
        categories: true,
        brands: true
      }
    })
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
    const { products, categories, brands, ...discountData } = data
    return this.prismaService.discount.update({
      where: { id, deletedAt: null },
      data: {
        ...discountData,
        updatedById,
        products: products ? { set: products.map((id) => ({ id })) } : undefined,
        categories: categories ? { set: categories.map((id) => ({ id })) } : undefined,
        brands: brands ? { set: brands.map((id) => ({ id })) } : undefined
      },
      include: {
        products: true,
        categories: true,
        brands: true
      }
    })
  }

  /**
   * Xóa mềm hoặc xóa cứng discount
   */
  async delete({ id, deletedById }: { id: string; deletedById: string }, isHard?: boolean): Promise<DiscountType> {
    if (isHard) {
      return this.prismaService.discount.delete({ where: { id } })
    }
    return this.prismaService.discount.update({
      where: { id, deletedAt: null },
      data: { deletedAt: new Date(), deletedById }
    })
  }
}
