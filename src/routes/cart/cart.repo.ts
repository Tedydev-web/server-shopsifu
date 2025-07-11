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
  GetCartResType,
  UpdateCartItemBodyType
} from 'src/routes/cart/cart.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { SKUSchemaType } from 'src/shared/models/shared-sku.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'
import { I18nService } from 'nestjs-i18n'
import { PaginatedResult, PaginationArgs, paginate } from 'src/shared/utils/pagination.util'

@Injectable()
export class CartRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

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
    if (cartItem && isCreate && quantity + cartItem.quantity > sku.stock) {
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

  private async paginateCart(
    userId: number,
    languageId: string,
    pagination: PaginationArgs
  ): Promise<PaginatedResult<CartItemDetailType>> {
    const { search, sortBy, orderBy } = pagination

    // Tạo custom model để sử dụng với paginate utility
    const cartModel = {
      count: async () => {
        const searchCondition = search
          ? Prisma.sql`AND (
            "Product"."name" ILIKE ${`%${search}%`} OR
            "User"."name" ILIKE ${`%${search}%`} OR
            "SKU"."value" ILIKE ${`%${search}%`}
          )`
          : Prisma.sql``

        const result = await this.prismaService.$queryRaw<{ count: bigint }[]>`
          SELECT COUNT(DISTINCT "Product"."createdById") as count
          FROM "CartItem"
          JOIN "SKU" ON "CartItem"."skuId" = "SKU"."id"
          JOIN "Product" ON "SKU"."productId" = "Product"."id"
          LEFT JOIN "User" ON "Product"."createdById" = "User"."id"
          WHERE "CartItem"."userId" = ${userId}
            AND "Product"."deletedAt" IS NULL
            AND "Product"."publishedAt" IS NOT NULL
            AND "Product"."publishedAt" <= NOW()
            ${searchCondition}
        `
        return Number(result[0]?.count || 0)
      },
      findMany: async (args: any) => {
        const { skip, take } = args

        const searchCondition = search
          ? Prisma.sql`AND (
            "Product"."name" ILIKE ${`%${search}%`} OR
            "User"."name" ILIKE ${`%${search}%`} OR
            "SKU"."value" ILIKE ${`%${search}%`}
          )`
          : Prisma.sql``

        const orderByClause =
          sortBy === 'price'
            ? Prisma.sql`ORDER BY MAX("SKU"."price") ${orderBy === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
            : sortBy === 'name'
              ? Prisma.sql`ORDER BY MAX("Product"."name") ${orderBy === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
              : sortBy === 'shopName'
                ? Prisma.sql`ORDER BY MAX("User"."name") ${orderBy === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`}`
                : Prisma.sql`ORDER BY MAX("CartItem"."updatedAt") DESC`

        return this.prismaService.$queryRaw<CartItemDetailType[]>`
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
         ${orderByClause}
         LIMIT ${take} OFFSET ${skip}
       `
      }
    }

    return paginate(cartModel, pagination)
  }

  async list({
    userId,
    languageId,
    pagination
  }: {
    userId: number
    languageId: string
    pagination: PaginationArgs
  }): Promise<PaginatedResult<CartItemDetailType>> {
    return this.paginateCart(userId, languageId, pagination)
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
