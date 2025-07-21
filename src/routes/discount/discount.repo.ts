import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountTypeSchema } from 'src/shared/models/shared-discount.model'
import { DiscountListQueryType } from './discount.model'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  async findById(id: string) {
    return this.prismaService.discount.findUnique({
      where: { id, deletedAt: null }
    })
  }

  async list(query: DiscountListQueryType & { shopId?: string }) {
    const { page = 1, limit = 10, shopId, isPublic, status, search } = query
    const where: any = { deletedAt: null }
    if (shopId) where.shopId = shopId
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
          products: { select: { id: true } } // <--- Lấy kèm danh sách productId
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

  async create({
    createdById,
    data
  }: {
    createdById: string | null
    data: Omit<DiscountTypeSchema, 'id' | 'createdAt' | 'updatedAt' | 'deletedAt' | 'usesCount' | 'usersUsed'>
  }) {
    return this.prismaService.discount.create({
      data: {
        ...data,
        createdById: createdById ?? undefined,
        usesCount: 0,
        usersUsed: [],
        shopId: data.shopId ?? undefined,
        canSaveBeforeStart: data.canSaveBeforeStart ?? false,
        isPublic: data.isPublic ?? true,
        updatedById: undefined,
        deletedById: undefined
      }
    })
  }

  async update({ id, updatedById, data }: { id: string; updatedById: string; data: Partial<DiscountTypeSchema> }) {
    return this.prismaService.discount.update({
      where: { id, deletedAt: null },
      data: {
        ...data,
        updatedById
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
