import { Injectable } from '@nestjs/common'
import {
  GetProductDetailResType,
  GetProductsQueryType,
  GetProductsResType,
  ProductType,
} from 'src/routes/product/product.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PaginationService } from 'src/shared/services/pagination.service'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class ProductRepo {
  constructor(
    private readonly paginationService: PaginationService,
    private readonly prismaService: PrismaService,
  ) {}

  async list(query: GetProductsQueryType, languageId: string): Promise<GetProductsResType> {
    const { brandIds, categories, minPrice, maxPrice } = query
    const where: any = {
      deletedAt: null,
    }

    if (brandIds?.length) {
      where.brandId = { in: brandIds }
    }

    if (categories?.length) {
      where.categories = {
        some: {
          categoryId: {
            in: categories,
          },
        },
      }
    }

    if (minPrice !== undefined) {
      where.basePrice = { ...where.basePrice, gte: minPrice }
    }

    if (maxPrice !== undefined) {
      where.basePrice = { ...where.basePrice, lte: maxPrice }
    }

    return this.paginationService.paginate('product', query, where, {
      include: {
        productTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { languageId, deletedAt: null },
        },
      },
      orderBy: [{ createdAt: 'desc' }],
    })
  }
  findById(id: number, languageId: string): Promise<GetProductDetailResType | null> {
    return this.prismaService.product.findUnique({
      where: {
        id,
        deletedAt: null,
      },
      include: {
        productTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { languageId, deletedAt: null },
        },
        skus: {
          where: {
            deletedAt: null,
          },
        },
        brand: {
          include: {
            brandTranslations: {
              where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { languageId, deletedAt: null },
            },
          },
        },
        categories: {
          where: {
            deletedAt: null,
          },
          include: {
            categoryTranslations: {
              where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { languageId, deletedAt: null },
            },
          },
        },
      },
    })
  }

  async delete(
    {
      id,
      deletedById,
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean,
  ): Promise<ProductType> {
    if (isHard) {
      const [product] = await Promise.all([
        this.prismaService.product.delete({
          where: {
            id,
          },
        }),
        this.prismaService.sKU.deleteMany({
          where: {
            productId: id,
          },
        }),
      ])
      return product
    }
    const now = new Date()
    const [product] = await Promise.all([
      this.prismaService.product.update({
        where: {
          id,
          deletedAt: null,
        },
        data: {
          deletedAt: now,
          deletedById,
        },
      }),
      this.prismaService.sKU.updateMany({
        where: {
          productId: id,
          deletedAt: null,
        },
        data: {
          deletedAt: now,
          deletedById,
        },
      }),
    ])
    return product
  }
}
