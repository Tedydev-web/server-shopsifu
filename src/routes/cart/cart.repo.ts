import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { NotFoundSKUException, OutOfStockSKUException, ProductNotFoundException } from 'src/routes/cart/cart.error'
import {
  AddToCartBodyType,
  CartItemDetailType,
  CartItemType,
  DeleteCartBodyType,
  GetCartQueryType,
  GetCartResType,
  UpdateCartItemBodyType,
} from 'src/routes/cart/cart.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { SKUSchemaType } from 'src/shared/models/shared-sku.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaginationService } from 'src/shared/services/pagination.service'

@Injectable()
export class CartRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paginationService: PaginationService,
  ) {}

  private async validateSKU(skuId: number, quantity: number): Promise<SKUSchemaType> {
    const sku = await this.prismaService.sKU.findUnique({
      where: { id: skuId, deletedAt: null },
      include: {
        product: true,
      },
    })
    // Kiểm tra tồn tại của SKU
    if (!sku) {
      throw NotFoundSKUException
    }
    // Kiểm tra lượng hàng còn lại
    if (sku.stock < 1 || sku.stock < quantity) {
      throw OutOfStockSKUException
    }
    const { product } = sku

    // Kiểm tra sản phẩm đã bị xóa hoặc có công khai hay không
    if (
      product.deletedAt !== null ||
      product.publishedAt === null ||
      (product.publishedAt !== null && product.publishedAt > new Date())
    ) {
      throw ProductNotFoundException
    }
    return sku
  }

  async list(query: {
    userId: number
    languageId: string
    limit?: number
    cursor?: string
    offset?: number
  }): Promise<GetCartResType> {
    const { userId, languageId, limit = 10, cursor, offset = 0 } = query

    // Sử dụng PaginationService để paginate cart items
    const paginationQuery = {
      limit,
      cursor,
      offset,
      sortOrder: 'desc' as const,
      sortBy: 'updatedAt',
    }

    const cartItemsResult = await this.paginationService.paginate(
      'cartItem',
      paginationQuery,
      {
        userId,
        sku: {
          product: {
            deletedAt: null,
            publishedAt: {
              not: null,
              lte: new Date(),
            },
          },
        },
      },
      {
        include: {
          sku: {
            include: {
              product: {
                include: {
                  productTranslations: {
                    where: {
                      deletedAt: null,
                      ...(languageId !== 'all' && { languageId }),
                    },
                  },
                  createdBy: {
                    select: {
                      id: true,
                      name: true,
                      avatar: true,
                    },
                  },
                },
              },
            },
          },
        },
        cursorFields: ['id'],
        orderBy: [{ updatedAt: 'desc' }],
      },
    )

    // Group cart items by shop
    const shopMap = new Map()

    cartItemsResult.data.forEach((cartItem: any) => {
      const shopId = cartItem.sku.product.createdBy.id
      const shop = cartItem.sku.product.createdBy

      if (!shopMap.has(shopId)) {
        shopMap.set(shopId, {
          shop,
          cartItems: [],
        })
      }

      shopMap.get(shopId).cartItems.push({
        id: cartItem.id,
        quantity: cartItem.quantity,
        skuId: cartItem.skuId,
        userId: cartItem.userId,
        createdAt: cartItem.createdAt,
        updatedAt: cartItem.updatedAt,
        sku: {
          id: cartItem.sku.id,
          value: cartItem.sku.value,
          price: cartItem.sku.price,
          stock: cartItem.sku.stock,
          image: cartItem.sku.image,
          productId: cartItem.sku.productId,
          product: {
            id: cartItem.sku.product.id,
            publishedAt: cartItem.sku.product.publishedAt,
            name: cartItem.sku.product.name,
            basePrice: cartItem.sku.product.basePrice,
            virtualPrice: cartItem.sku.product.virtualPrice,
            brandId: cartItem.sku.product.brandId,
            images: cartItem.sku.product.images,
            variants: cartItem.sku.product.variants,
            productTranslations: cartItem.sku.product.productTranslations,
          },
        },
      })
    })

    const data = Array.from(shopMap.values())

    return {
      data,
      metadata: cartItemsResult.metadata,
    }
  }

  async create(userId: number, body: AddToCartBodyType): Promise<CartItemType> {
    await this.validateSKU(body.skuId, body.quantity)

    return this.prismaService.cartItem.upsert({
      where: {
        userId_skuId: {
          userId,
          skuId: body.skuId,
        },
      },
      update: {
        quantity: {
          increment: body.quantity,
        },
      },
      create: {
        userId,
        skuId: body.skuId,
        quantity: body.quantity,
      },
    })
  }

  async update(cartItemId: number, body: UpdateCartItemBodyType): Promise<CartItemType> {
    await this.validateSKU(body.skuId, body.quantity)

    return this.prismaService.cartItem.update({
      where: {
        id: cartItemId,
      },
      data: {
        skuId: body.skuId,
        quantity: body.quantity,
      },
    })
  }

  delete(userId: number, body: DeleteCartBodyType): Promise<{ count: number }> {
    return this.prismaService.cartItem.deleteMany({
      where: {
        id: {
          in: body.cartItemIds,
        },
        userId,
      },
    })
  }
}
