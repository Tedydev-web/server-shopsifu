import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountStatus } from 'src/shared/constants/discount.constant'
import { GetManageDiscountsQueryType, CreateDiscountBodyType, UpdateDiscountBodyType } from './discount.model'
import { DiscountType } from 'src/shared/models/shared-discount.model'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Lấy danh sách discount cho quản lý
   */
  async list(query: GetManageDiscountsQueryType) {
    const { page, limit } = query
    const skip = (page - 1) * limit
    const take = limit

    const where: Prisma.DiscountWhereInput = {
      deletedAt: null,
      ...(query.shopId && { shopId: query.shopId }),
      ...(query.status && { status: query.status }),
      ...(query.search && {
        OR: [
          { name: { contains: query.search, mode: 'insensitive' } },
          { code: { contains: query.search, mode: 'insensitive' } }
        ]
      })
    }

    const [totalItems, data] = await Promise.all([
      this.prismaService.discount.count({ where }),
      this.prismaService.discount.findMany({
        where,
        include: {
          products: { select: { id: true, name: true } },
          categories: { select: { id: true, name: true } },
          brands: { select: { id: true, name: true } }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take
      })
    ])

    return {
      data,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages: Math.ceil(totalItems / limit),
        hasNext: page < Math.ceil(totalItems / limit),
        hasPrev: page > 1
      }
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
   * Lấy chi tiết discount
   */
  async getDetail(discountId: string) {
    return this.prismaService.discount
      .findUnique({
        where: {
          id: discountId,
          deletedAt: null
        },
        include: {
          products: {
            where: { deletedAt: null },
            select: { id: true, name: true }
          },
          categories: {
            where: { deletedAt: null },
            select: { id: true, name: true }
          },
          brands: {
            where: { deletedAt: null },
            select: { id: true, name: true }
          },
          discountSnapshots: {
            select: { id: true, orderId: true, discountAmount: true, createdAt: true }
          }
        }
      })
      .then((discount) => (discount ? { data: discount } : null))
  }

  /**
   * Tạo discount mới
   */
  async create({ createdById, data }: { createdById: string; data: CreateDiscountBodyType }) {
    const { productIds, categoryIds, brandIds, ...discountData } = data

    return this.prismaService.discount
      .create({
        data: {
          ...discountData,
          createdById,
          ...(productIds && {
            products: {
              connect: productIds.map((id) => ({ id }))
            }
          }),
          ...(categoryIds && {
            categories: {
              connect: categoryIds.map((id) => ({ id }))
            }
          }),
          ...(brandIds && {
            brands: {
              connect: brandIds.map((id) => ({ id }))
            }
          })
        },
        include: {
          products: { select: { id: true, name: true } },
          categories: { select: { id: true, name: true } },
          brands: { select: { id: true, name: true } }
        }
      })
      .then((discount) => ({ data: discount }))
  }

  /**
   * Cập nhật discount
   */
  async update({ id, updatedById, data }: { id: string; updatedById: string; data: UpdateDiscountBodyType }) {
    const { productIds, categoryIds, brandIds, ...discountData } = data

    return this.prismaService.$transaction(async (tx) => {
      // Cập nhật discount
      const discount = await tx.discount.update({
        where: {
          id,
          deletedAt: null
        },
        data: {
          ...discountData,
          updatedById,
          ...(productIds && {
            products: {
              set: productIds.map((id) => ({ id }))
            }
          }),
          ...(categoryIds && {
            categories: {
              set: categoryIds.map((id) => ({ id }))
            }
          }),
          ...(brandIds && {
            brands: {
              set: brandIds.map((id) => ({ id }))
            }
          })
        },
        include: {
          products: { select: { id: true, name: true } },
          categories: { select: { id: true, name: true } },
          brands: { select: { id: true, name: true } }
        }
      })

      return discount
    })
  }

  /**
   * Xóa discount (soft delete)
   */
  async delete({ id, deletedById }: { id: string; deletedById: string }): Promise<DiscountType> {
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
   * Lấy danh sách discount khả dụng cho checkout
   */
  async getAvailableDiscounts(cartItems: any[], userId?: string) {
    const now = new Date()
    const subtotal = cartItems.reduce((sum, item) => sum + item.sku.price * item.quantity, 0)

    return await this.prismaService.discount.findMany({
      where: {
        status: DiscountStatus.ACTIVE,
        startDate: { lte: now },
        endDate: { gte: now },
        minOrderValue: { lte: subtotal },
        deletedAt: null,
        OR: [
          { maxUses: 0 }, // Không giới hạn
          { usesCount: { lt: this.prismaService.discount.fields.maxUses } }
        ],
        ...(userId && {
          OR: [{ isPublic: true }, { shopId: userId }]
        })
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })
  }

  /**
   * Lấy discount theo codes
   */
  async getDiscountsByCodes(codes: string[]) {
    return await this.prismaService.discount.findMany({
      where: {
        code: { in: codes },
        status: DiscountStatus.ACTIVE,
        startDate: { lte: new Date() },
        endDate: { gte: new Date() },
        deletedAt: null
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })
  }
}
