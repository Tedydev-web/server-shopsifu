import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountTypeSchema } from 'src/shared/models/shared-discount.model'
import { GetManageDiscountsQueryType } from './discount.model'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  async findById(id: string) {
    return this.prismaService.discount.findUnique({
      where: { id, deletedAt: null },
      include: {
        products: true
      }
    })
  }

  async list(query: GetManageDiscountsQueryType) {
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
          products: true
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

  async findByCode(code: string) {
    return this.prismaService.discount.findFirst({
      where: { code, deletedAt: null },
      include: {
        products: true
      }
    })
  }

  async create({ createdById, data }: { createdById: string; data: any }) {
    const { products, ...discountData } = data
    return this.prismaService.discount.create({
      data: {
        ...discountData,
        createdById,
        products: products && products.length > 0 ? { connect: products.map((id: string) => ({ id })) } : undefined
      },
      include: {
        products: true
      }
    })
  }

  async update({ id, updatedById, data }: { id: string; updatedById: string; data: any }) {
    const { products, ...discountData } = data
    return this.prismaService.discount.update({
      where: { id, deletedAt: null },
      data: {
        ...discountData,
        updatedById,
        products: products ? { set: products.map((id: string) => ({ id })) } : undefined
      },
      include: {
        products: true
      }
    })
  }

  async delete({ id, deletedById }: { id: string; deletedById: string }, isHard?: boolean) {
    if (isHard) {
      return this.prismaService.discount.delete({ where: { id } })
    }
    return this.prismaService.discount.update({
      where: { id, deletedAt: null },
      data: { deletedAt: new Date(), deletedById }
    })
  }
}
