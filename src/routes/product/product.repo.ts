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

  create({
    createdById,
    data,
  }: {
    createdById: number
    data: CreateProductBodyType
  }): Promise<GetProductDetailResType> {
    const { skus, categories, ...productData } = data
    return this.prismaService.product.create({
      data: {
        createdById,
        ...productData,
        categories: {
          connect: categories.map((category) => ({ id: category })),
        },
        skus: {
          createMany: {
            data: skus,
          },
        },
      },
      include: {
        productTranslations: {
          where: { deletedAt: null },
        },
        skus: {
          where: { deletedAt: null },
        },
        brand: {
          include: {
            brandTranslations: {
              where: { deletedAt: null },
            },
          },
        },
        categories: {
          where: {
            deletedAt: null,
          },
          include: {
            categoryTranslations: {
              where: { deletedAt: null },
            },
          },
        },
      },
    })
  }

  async update({
    id,
    updatedById,
    data,
  }: {
    id: number
    updatedById: number
    data: UpdateProductBodyType
  }): Promise<ProductType> {
    const { skus: dataSkus, categories, ...productData } = data
    // SKU đã tồn tại trong DB nhưng không có trong data payload thì sẽ bị xóa
    // SKU đã tồn tại trong DB nhưng có trong data payload thì sẽ được cập nhật
    // SKY không tồn tại trong DB nhưng có trong data payload thì sẽ được thêm mới

    // 1. Lấy danh sách SKU hiện tại trong DB
    const existingSKUs = await this.prismaService.sKU.findMany({
      where: {
        productId: id,
        deletedAt: null,
      },
    })

    // 2. Tìm các SKUs cần xóa (tồn tại trong DB nhưng không có trong data payload)
    const skusToDelete = existingSKUs.filter((sku) => dataSkus.every((dataSku) => dataSku.value !== sku.value))
    const skuIdsToDelete = skusToDelete.map((sku) => sku.id)

    // 3. Mapping ID vào trong data payload
    const skusWithId = dataSkus.map((dataSku) => {
      const existingSku = existingSKUs.find((existingSKU) => existingSKU.value === dataSku.value)
      return {
        ...dataSku,
        id: existingSku ? existingSku.id : null,
      }
    })

    // 4. Tìm các skus để cập nhật
    const skusToUpdate = skusWithId.filter((sku) => sku.id !== null)

    // 5. Tìm các skus để thêm mới
    const skusToCreate = skusWithId
      .filter((sku) => sku.id === null)
      .map((sku) => {
        const { id: skuId, ...data } = sku
        return {
          ...data,
          productId: id,
          createdById: updatedById,
        }
      })
    const [product] = await this.prismaService.$transaction([
      // Cập nhật Product
      this.prismaService.product.update({
        where: {
          id,
          deletedAt: null,
        },
        data: {
          ...productData,
          updatedById,
          categories: {
            connect: categories.map((category) => ({ id: category })),
          },
        },
      }),
      // Xóa mềm các SKU không có trong data payload
      this.prismaService.sKU.updateMany({
        where: {
          id: {
            in: skuIdsToDelete,
          },
        },
        data: {
          deletedAt: new Date(),
          deletedById: updatedById,
        },
      }),
      // Cập nhật các SKU có trong data payload
      ...skusToUpdate.map((sku) =>
        this.prismaService.sKU.update({
          where: {
            id: sku.id as number,
          },
          data: {
            value: sku.value,
            price: sku.price,
            stock: sku.stock,
            image: sku.image,
            updatedById,
          },
        }),
      ),
      // Thêm mới các SKU không có trong DB
      this.prismaService.sKU.createMany({
        data: skusToCreate,
      }),
    ])

    return product
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
