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

  async list(query: { userId: number; languageId: string; page?: number; limit?: number }): Promise<GetCartResType> {
    const { userId, languageId, page = 1, limit = 10 } = query
    const skip = (page - 1) * limit

    // Đếm tổng số nhóm sản phẩm (shops) - optimized
    const totalShopsQuery = this.prismaService.$queryRaw<{ count: bigint }[]>`
      SELECT COUNT(DISTINCT "Product"."createdById") as count
      FROM "CartItem"
      JOIN "SKU" ON "CartItem"."skuId" = "SKU"."id"
      JOIN "Product" ON "SKU"."productId" = "Product"."id"
      WHERE "CartItem"."userId" = ${userId}
        AND "Product"."deletedAt" IS NULL
        AND "Product"."publishedAt" IS NOT NULL
        AND "Product"."publishedAt" <= NOW()
    `

    // Lấy data với GROUP BY và JSON aggregation - highly optimized
    const dataQuery = this.prismaService.$queryRaw<
      {
        shop: { id: number; name: string; avatar: string | null }
        cartItems: any[]
      }[]
    >`
      SELECT
        jsonb_build_object(
          'id', "User"."id",
          'name', "User"."name",
          'avatar', "User"."avatar"
        ) AS "shop",
        json_agg(
          jsonb_build_object(
            'id', "CartItem"."id",
            'quantity', "CartItem"."quantity",
            'skuId', "CartItem"."skuId",
            'userId', "CartItem"."userId",
            'createdAt', "CartItem"."createdAt",
            'updatedAt', "CartItem"."updatedAt",
            'sku', jsonb_build_object(
              'id', "SKU"."id",
              'value', "SKU"."value",
              'price', "SKU"."price",
              'stock', "SKU"."stock",
              'image', "SKU"."image",
              'productId', "SKU"."productId",
              'product', jsonb_build_object(
                'id', "Product"."id",
                'publishedAt', "Product"."publishedAt",
                'name', "Product"."name",
                'basePrice', "Product"."basePrice",
                'virtualPrice', "Product"."virtualPrice",
                'brandId', "Product"."brandId",
                'images', "Product"."images",
                'variants', "Product"."variants",
                'productTranslations', COALESCE((
                  SELECT json_agg(
                    jsonb_build_object(
                      'id', pt."id",
                      'productId', pt."productId",
                      'languageId', pt."languageId",
                      'name', pt."name",
                      'description', pt."description"
                    )
                  ) FILTER (WHERE pt."id" IS NOT NULL)
                  FROM "ProductTranslation" pt
                  WHERE pt."productId" = "Product"."id"
                    AND pt."deletedAt" IS NULL
                    ${languageId === ALL_LANGUAGE_CODE ? Prisma.sql`` : Prisma.sql`AND pt."languageId" = ${languageId}`}
                ), '[]'::json)
              )
            )
          ) ORDER BY "CartItem"."updatedAt" DESC
        ) AS "cartItems"
      FROM "CartItem"
      JOIN "SKU" ON "CartItem"."skuId" = "SKU"."id"
      JOIN "Product" ON "SKU"."productId" = "Product"."id"
      LEFT JOIN "User" ON "Product"."createdById" = "User"."id"
      WHERE "CartItem"."userId" = ${userId}
        AND "Product"."deletedAt" IS NULL
        AND "Product"."publishedAt" IS NOT NULL
        AND "Product"."publishedAt" <= NOW()
      GROUP BY "Product"."createdById", "User"."id", "User"."name", "User"."avatar"
      ORDER BY MAX("CartItem"."updatedAt") DESC
      LIMIT ${limit}
      OFFSET ${skip}
    `

    // Execute parallel queries cho performance tốt nhất
    const [data, totalShopsResult] = await Promise.all([dataQuery, totalShopsQuery])
    const totalItems = Number(totalShopsResult[0]?.count || 0)

    // Sử dụng PaginationService chuẩn cho metadata
    const metadata = this.paginationService.createPaginationMetadata(
      { page, limit, sortOrder: 'desc' as const },
      totalItems,
    )

    return {
      data,
      metadata,
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
