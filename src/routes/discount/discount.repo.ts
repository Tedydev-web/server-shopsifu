import { Injectable } from '@nestjs/common'
import {
  GetManageDiscountsResType,
  GetDiscountDetailResType,
  CreateDiscountBodyType,
  UpdateDiscountBodyType
} from './discount.model'
import { DiscountType } from 'src/shared/models/shared-discount.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'

@Injectable()
export class DiscountRepo {
  constructor(private readonly prismaService: PrismaService) {}

  async list({
    limit,
    page,
    name,
    code,
    discountStatus,
    discountType,
    discountApplyType,
    voucherType,
    displayType,
    isPlatform,
    startDate,
    endDate,
    minValue,
    maxValue,
    shopId,
    createdById,
    orderBy,
    sortBy
  }: {
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
    createdById: string
    orderBy: string
    sortBy: string
  }): Promise<GetManageDiscountsResType> {
    const skip = (page - 1) * limit
    const take = limit

    const where: Prisma.DiscountWhereInput = {
      deletedAt: null,
      createdById: createdById
    }

    if (name) {
      where.name = {
        contains: name,
        mode: 'insensitive'
      }
    }

    if (code) {
      where.code = {
        contains: code,
        mode: 'insensitive'
      }
    }

    if (discountStatus) {
      where.discountStatus = discountStatus as any
    }

    if (discountType) {
      where.discountType = discountType as any
    }

    if (discountApplyType) {
      where.discountApplyType = discountApplyType as any
    }

    if (voucherType) {
      where.voucherType = voucherType as any
    }

    if (displayType) {
      where.displayType = displayType as any
    }

    if (isPlatform !== undefined) {
      where.isPlatform = isPlatform
    }

    if (startDate) {
      where.startDate = {
        gte: startDate
      }
    }

    if (endDate) {
      where.endDate = {
        lte: endDate
      }
    }

    if (minValue !== undefined || maxValue !== undefined) {
      where.value = {
        gte: minValue,
        lte: maxValue
      }
    }

    if (shopId) {
      where.shopId = shopId
    }

    // Mặc định sort theo createdAt mới nhất
    let calculatedOrderBy: Prisma.DiscountOrderByWithRelationInput | Prisma.DiscountOrderByWithRelationInput[] = {
      createdAt: orderBy as any
    }

    if (sortBy === 'value') {
      calculatedOrderBy = {
        value: orderBy as any
      }
    } else if (sortBy === 'usesCount') {
      calculatedOrderBy = {
        usesCount: orderBy as any
      }
    }

    const [totalItems, data] = await Promise.all([
      this.prismaService.discount.count({
        where
      }),
      this.prismaService.discount.findMany({
        where,
        orderBy: calculatedOrderBy,
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

  findById(discountId: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findUnique({
      where: {
        id: discountId,
        deletedAt: null
      }
    })
  }

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
          brands: brands
            ? {
                connect: brands.map((brandId) => ({ id: brandId }))
              }
            : undefined,
          categories: categories
            ? {
                connect: categories.map((categoryId) => ({ id: categoryId }))
              }
            : undefined,
          products: products
            ? {
                connect: products.map((productId) => ({ id: productId }))
              }
            : undefined
        }
      })
      .then((discount) => ({ data: discount }))
  }

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
        brands: brands
          ? {
              set: brands.map((brandId) => ({ id: brandId }))
            }
          : undefined,
        categories: categories
          ? {
              set: categories.map((categoryId) => ({ id: categoryId }))
            }
          : undefined,
        products: products
          ? {
              set: products.map((productId) => ({ id: productId }))
            }
          : undefined
      }
    })
  }

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
        where: {
          id
        }
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

  findByCode(code: string): Promise<DiscountType | null> {
    return this.prismaService.discount.findUnique({
      where: {
        code,
        deletedAt: null
      }
    })
  }
}
