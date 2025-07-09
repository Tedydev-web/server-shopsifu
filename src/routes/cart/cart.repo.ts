import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import {
  InvalidQuantityException,
  NotFoundCartItemException,
  NotFoundSKUException,
  OutOfStockSKUException,
  ProductNotFoundException
} from 'src/routes/cart/cart.error'
import {
  AddToCartBodyType,
  CartItemDetailType,
  CartItemType,
  DeleteCartBodyType,
  GetCartQueryType,
  GetCartResType,
  UpdateCartItemBodyType
} from 'src/routes/cart/cart.model'
import { ALL_LANGUAGE_CODE, OrderBy, SortBy } from 'src/shared/constants/other.constant'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { SKUSchemaType } from 'src/shared/models/shared-sku.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class CartRepo {
  constructor(private readonly prismaService: PrismaService) {}

  private async validateSKU({
    skuId,
    quantity,
    userId,
    isCreate
  }: {
    skuId: number
    quantity: number
    userId: number
    isCreate: boolean
  }): Promise<SKUSchemaType> {
    const [cartItem, sku] = await Promise.all([
      this.prismaService.cartItem.findUnique({
        where: {
          userId_skuId: {
            userId,
            skuId
          }
        }
      }),
      this.prismaService.sKU.findUnique({
        where: { id: skuId, deletedAt: null },
        include: {
          product: true
        }
      })
    ])
    // Kiểm tra tồn tại của SKU
    if (!sku) {
      throw NotFoundSKUException
    }
    if (!cartItem) {
      throw NotFoundCartItemException
    }
    if (isCreate && quantity + cartItem.quantity > sku.stock) {
      throw InvalidQuantityException
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

  async list({
    userId,
    languageId,
    page,
    limit,
    search,
    sortBy,
    orderBy
  }: {
    userId: number
    languageId: string
    page: number
    limit: number
    search?: string
    sortBy?: string
    orderBy?: string
  }): Promise<GetCartResType> {
    const skip = (page - 1) * limit
    const take = limit

    // Xây dựng điều kiện search
    const searchCondition = search
      ? Prisma.sql`AND (
        "User"."name" ILIKE ${`%${search}%`} OR
        "Product"."name" ILIKE ${`%${search}%`} OR
        EXISTS (
          SELECT 1 FROM "ProductTranslation" pt 
          WHERE pt."productId" = "Product"."id" 
            AND pt."deletedAt" IS NULL
            ${languageId === ALL_LANGUAGE_CODE ? Prisma.sql`` : Prisma.sql`AND pt."languageId" = ${languageId}`}
            AND pt."name" ILIKE ${`%${search}%`}
        )
      )`
      : Prisma.sql``

    // Xây dựng điều kiện sort
    let orderByClause: Prisma.Sql
    switch (sortBy) {
      case SortBy.ShopName:
        orderByClause = Prisma.sql`"User"."name" ${orderBy === OrderBy.Asc ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
        break
      case SortBy.CreatedAt:
        orderByClause = Prisma.sql`MAX("CartItem"."createdAt") ${orderBy === OrderBy.Asc ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
        break
      case SortBy.UpdatedAt:
      default:
        orderByClause = Prisma.sql`MAX("CartItem"."updatedAt") ${orderBy === OrderBy.Asc ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
        break
    }

    // Đếm tổng số nhóm sản phẩm với điều kiện search
    const totalItems$ = this.prismaService.$queryRaw<{ createdById: number }[]>`
      SELECT
        "Product"."createdById"
      FROM "CartItem"
      JOIN "SKU" ON "CartItem"."skuId" = "SKU"."id"
      JOIN "Product" ON "SKU"."productId" = "Product"."id"
      LEFT JOIN "User" ON "Product"."createdById" = "User"."id"
      WHERE "CartItem"."userId" = ${userId}
        AND "Product"."deletedAt" IS NULL
        AND "Product"."publishedAt" IS NOT NULL
        AND "Product"."publishedAt" <= NOW()
        ${searchCondition}
      GROUP BY "Product"."createdById"
    `

    // Query chính với pagination, search và sort
    const data$ = this.prismaService.$queryRaw<CartItemDetailType[]>`
     SELECT
       "Product"."createdById",
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
       ) AS "cartItems",
       jsonb_build_object(
         'id', "User"."id",
         'name', "User"."name",
         'avatar', "User"."avatar"
       ) AS "shop"
     FROM "CartItem"
     JOIN "SKU" ON "CartItem"."skuId" = "SKU"."id"
     JOIN "Product" ON "SKU"."productId" = "Product"."id"
     LEFT JOIN "ProductTranslation" ON "Product"."id" = "ProductTranslation"."productId"
       AND "ProductTranslation"."deletedAt" IS NULL
       ${languageId === ALL_LANGUAGE_CODE ? Prisma.sql`` : Prisma.sql`AND "ProductTranslation"."languageId" = ${languageId}`}
     LEFT JOIN "User" ON "Product"."createdById" = "User"."id"
     WHERE "CartItem"."userId" = ${userId}
        AND "Product"."deletedAt" IS NULL
        AND "Product"."publishedAt" IS NOT NULL
        AND "Product"."publishedAt" <= NOW()
        ${searchCondition}
     GROUP BY "Product"."createdById", "User"."id"
     ORDER BY ${orderByClause}
      LIMIT ${take} 
      OFFSET ${skip}
   `

    const [data, totalItems] = await Promise.all([data$, totalItems$])

    return {
      data,
      metadata: {
        totalItems: totalItems.length,
        page,
        limit,
        totalPages: Math.ceil(totalItems.length / limit),
        hasNext: page < Math.ceil(totalItems.length / limit),
        hasPrev: page > 1
      }
    }
  }

  async create(userId: number, body: AddToCartBodyType): Promise<CartItemType> {
    await this.validateSKU({
      skuId: body.skuId,
      quantity: body.quantity,
      userId,
      isCreate: true
    })

    return this.prismaService.cartItem.upsert({
      where: {
        userId_skuId: {
          userId,
          skuId: body.skuId
        }
      },
      update: {
        quantity: {
          increment: body.quantity
        }
      },
      create: {
        userId,
        skuId: body.skuId,
        quantity: body.quantity
      }
    })
  }

  async update({
    userId,
    body,
    cartItemId
  }: {
    userId: number
    cartItemId: number
    body: UpdateCartItemBodyType
  }): Promise<CartItemType> {
    await this.validateSKU({
      skuId: body.skuId,
      quantity: body.quantity,
      userId,
      isCreate: false
    })

    return this.prismaService.cartItem
      .update({
        where: {
          id: cartItemId,
          userId
        },
        data: {
          skuId: body.skuId,
          quantity: body.quantity
        }
      })
      .catch((error) => {
        if (isNotFoundPrismaError(error)) {
          throw NotFoundCartItemException
        }
        throw error
      })
  }

  delete(userId: number, body: DeleteCartBodyType): Promise<{ count: number }> {
    return this.prismaService.cartItem.deleteMany({
      where: {
        id: {
          in: body.cartItemIds
        },
        userId
      }
    })
  }
}
