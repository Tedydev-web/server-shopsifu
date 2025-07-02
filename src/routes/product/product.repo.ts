import { Injectable } from '@nestjs/common'
import { GetProductsQueryType, GetProductsResType } from 'src/routes/product/product.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PaginationService } from 'src/shared/services/pagination.service'

@Injectable()
export class ProductRepo {
  constructor(private readonly paginationService: PaginationService) {}

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
}
