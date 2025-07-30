import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { OrderStatus } from 'src/shared/constants/order.constant'
import {
  CannotCancelOrderException,
  NotFoundCartItemException,
  OrderNotFoundException,
  OutOfStockSKUException,
  ProductNotFoundException,
  SKUNotBelongToShopException
} from 'src/routes/order/order.error'
import {
  CancelOrderResType,
  CreateOrderBodyType,
  CreateOrderResType,
  GetOrderDetailResType,
  GetOrderListQueryType,
  GetOrderListResType
} from 'src/routes/order/order.model'
import { OrderProducer } from 'src/routes/order/order.producer'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { VersionConflictException } from 'src/shared/error'
import { calculateDiscountAmount, isNotFoundPrismaError } from 'src/shared/helpers'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountApplyType, DiscountStatus } from 'src/shared/constants/discount.constant'

@Injectable()
export class OrderRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private orderProducer: OrderProducer,
    private readonly configService: ConfigService
  ) {}
  async list(userId: string, query: GetOrderListQueryType): Promise<GetOrderListResType> {
    const { page, limit, status } = query
    const skip = (page - 1) * limit
    const take = limit
    const where: Prisma.OrderWhereInput = {
      userId,
      status
    }

    // Đếm tổng số order
    const totalItem$ = this.prismaService.order.count({
      where
    })
    // Lấy list order
    const data$ = await this.prismaService.order.findMany({
      where,
      include: {
        items: true
      },
      skip,
      take,
      orderBy: {
        createdAt: 'desc'
      }
    })
    const [data, totalItems] = await Promise.all([data$, totalItem$])
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

  async create(
    userId: string,
    body: CreateOrderBodyType
  ): Promise<{
    paymentId: number
    orders: CreateOrderResType['data']['orders']
  }> {
    // 1. Kiểm tra xem tất cả cartItemIds có tồn tại trong cơ sở dữ liệu hay không
    // 2. Kiểm tra số lượng mua có lớn hơn số lượng tồn kho hay không
    // 3. Kiểm tra xem tất cả sản phẩm mua có sản phẩm nào bị xóa hay ẩn không
    // 4. Kiểm tra xem các skuId trong cartItem gửi lên có thuộc về shopid gửi lên không
    // 5. Tạo order
    // 6. Xóa cartItem
    const allBodyCartItemIds = body.map((item) => item.cartItemIds).flat()
    const cartItemsForSKUId = await this.prismaService.cartItem.findMany({
      where: {
        id: {
          in: allBodyCartItemIds
        },
        userId
      },
      select: {
        skuId: true
      }
    })
    const skuIds = cartItemsForSKUId.map((cartItem) => cartItem.skuId)

    // Lock tất cả các SKU cần mua
    const redlock = this.configService.get('redis.redlock')
    const locks = await Promise.all(skuIds.map((skuId) => redlock.acquire([`lock:sku:${skuId}`], 3000))) // Giữ khóa trong 3 giây

    try {
      const [paymentId, orders] = await this.prismaService.$transaction<[number, CreateOrderResType['data']['orders']]>(
        async (tx) => {
          // await tx.$queryRaw`SELECT * FROM "SKU" WHERE id IN (${Prisma.join(skuIds)}) FOR UPDATE`
          const cartItems = await tx.cartItem.findMany({
            where: {
              id: {
                in: allBodyCartItemIds
              },
              userId
            },
            include: {
              sku: {
                include: {
                  product: {
                    include: {
                      productTranslations: true
                    }
                  }
                }
              }
            }
          })

          // 1. Kiểm tra xem tất cả cartItemIds có tồn tại trong cơ sở dữ liệu hay không
          if (cartItems.length !== allBodyCartItemIds.length) {
            throw NotFoundCartItemException
          }

          // 2. Kiểm tra số lượng mua có lớn hơn số lượng tồn kho hay không
          const isOutOfStock = cartItems.some((item) => {
            return item.sku.stock < item.quantity
          })
          if (isOutOfStock) {
            throw OutOfStockSKUException
          }

          // 3. Kiểm tra xem tất cả sản phẩm mua có sản phẩm nào bị xóa hay ẩn không
          const isExistNotReadyProduct = cartItems.some(
            (item) =>
              item.sku.product.deletedAt !== null ||
              item.sku.product.publishedAt === null ||
              item.sku.product.publishedAt > new Date()
          )
          if (isExistNotReadyProduct) {
            throw ProductNotFoundException
          }

          // 4. Kiểm tra xem các skuId trong cartItem gửi lên có thuộc về shopid gửi lên không
          const cartItemMap = new Map<string, (typeof cartItems)[0]>()
          cartItems.forEach((item) => {
            cartItemMap.set(item.id, item)
          })
          const isValidShop = body.every((item) => {
            const bodyCartItemIds = item.cartItemIds
            return bodyCartItemIds.every((cartItemId) => {
              // Neu đã đến bước này thì cartItem luôn luôn có giá trị
              // Vì chúng ta đã so sánh với allBodyCartItems.length ở trên rồi
              const cartItem = cartItemMap.get(cartItemId)!
              return item.shopId === cartItem.sku.createdById
            })
          })
          if (!isValidShop) {
            throw SKUNotBelongToShopException
          }

          // 5. Tạo order và xóa cartItem trong transaction để đảm bảo tính toàn vẹn dữ liệu

          const payment = await tx.payment.create({
            data: {
              status: PaymentStatus.PENDING
            }
          })
          const orders: CreateOrderResType['data']['orders'] = []
          for (const item of body) {
            // Tính tổng giá trị đơn hàng trước khi áp dụng discount
            const orderSubTotal = item.cartItemIds.reduce((sum, cartItemId) => {
              const cartItem = cartItemMap.get(cartItemId)!
              return sum + cartItem.sku.price * cartItem.quantity
            }, 0)

            // Xử lý discount nếu có
            const appliedDiscountsToCreate: any[] = []

            if (item.discountCodes && item.discountCodes.length > 0) {
              // Lấy thông tin các discount
              const discounts = await tx.discount.findMany({
                where: {
                  code: { in: item.discountCodes },
                  discountStatus: DiscountStatus.ACTIVE,
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

              // Tính toán giá trị giảm giá cho từng mã
              for (const discount of discounts) {
                const discountAmount = calculateDiscountAmount(discount, orderSubTotal)

                // Chuẩn bị dữ liệu để tạo DiscountSnapshot
                appliedDiscountsToCreate.push({
                  name: discount.name,
                  description: discount.description,
                  type: discount.discountType,
                  value: discount.value,
                  code: discount.code,
                  maxDiscountValue: discount.maxDiscountValue,
                  discountAmount: discountAmount,
                  minOrderValue: discount.minOrderValue,
                  isPlatform: discount.isPlatform,
                  voucherType: discount.voucherType,
                  displayType: discount.displayType,
                  discountApplyType: discount.discountApplyType,
                  targetInfo:
                    discount.discountApplyType === DiscountApplyType.SPECIFIC
                      ? {
                          productIds: discount.products.map((p) => p.id),
                          categoryIds: discount.categories.map((c) => c.id),
                          brandIds: discount.brands.map((b) => b.id)
                        }
                      : null,
                  discountId: discount.id
                })

                // Cập nhật số lượt sử dụng discount
                await tx.discount.update({
                  where: { id: discount.id },
                  data: {
                    usesCount: { increment: 1 },
                    usersUsed: { push: userId }
                  }
                })
              }
            }

            const order = await tx.order.create({
              data: {
                userId,
                status: OrderStatus.PENDING_PAYMENT,
                receiver: item.receiver,
                createdById: userId,
                shopId: item.shopId,
                paymentId: payment.id,
                items: {
                  create: item.cartItemIds.map((cartItemId) => {
                    const cartItem = cartItemMap.get(cartItemId)!
                    return {
                      productName: cartItem.sku.product.name,
                      skuPrice: cartItem.sku.price,
                      image: cartItem.sku.image,
                      skuId: cartItem.sku.id,
                      skuValue: cartItem.sku.value,
                      quantity: cartItem.quantity,
                      productId: cartItem.sku.product.id,
                      productTranslations: cartItem.sku.product.productTranslations.map((translation) => {
                        return {
                          id: translation.id,
                          name: translation.name,
                          description: translation.description,
                          languageId: translation.languageId
                        }
                      })
                    }
                  })
                },
                products: {
                  connect: item.cartItemIds.map((cartItemId) => {
                    const cartItem = cartItemMap.get(cartItemId)!
                    return {
                      id: cartItem.sku.product.id
                    }
                  })
                }
              }
            })

            // Tạo các DiscountSnapshot
            for (const discountData of appliedDiscountsToCreate) {
              await tx.discountSnapshot.create({
                data: {
                  ...discountData,
                  orderId: order.id
                }
              })
            }

            orders.push(order)
          }

          await tx.cartItem.deleteMany({
            where: {
              id: {
                in: allBodyCartItemIds
              }
            }
          })
          for (const item of cartItems) {
            await tx.sKU
              .update({
                where: {
                  id: item.sku.id,
                  updatedAt: item.sku.updatedAt, // Đảm bảo không có ai cập nhật SKU trong khi chúng ta đang xử lý
                  stock: {
                    gte: item.quantity // Đảm bảo số lượng tồn kho đủ để trừ
                  }
                },
                data: {
                  stock: {
                    decrement: item.quantity
                  }
                }
              })
              .catch((e) => {
                if (isNotFoundPrismaError(e)) {
                  throw VersionConflictException
                }
                throw e
              })
          }
          await this.orderProducer.addCancelPaymentJob(payment.id)
          return [payment.id, orders]
        }
      )

      return {
        paymentId,
        orders
      }
    } finally {
      // Giải phóng lock
      await Promise.all(locks.map((lock) => lock.release().catch(() => {})))
    }
  }

  async detail(userId: string, orderid: string): Promise<GetOrderDetailResType> {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderid,
        userId,
        deletedAt: null
      },
      include: {
        items: true
      }
    })
    if (!order) {
      throw OrderNotFoundException
    }
    return {
      data: order
    }
  }

  async cancel(userId: string, orderId: string): Promise<CancelOrderResType> {
    try {
      const order = await this.prismaService.order.findUniqueOrThrow({
        where: {
          id: orderId,
          userId,
          deletedAt: null
        }
      })
      if (order.status !== OrderStatus.PENDING_PAYMENT) {
        throw CannotCancelOrderException
      }
      const updatedOrder = await this.prismaService.order.update({
        where: {
          id: orderId,
          userId,
          deletedAt: null
        },
        data: {
          status: OrderStatus.CANCELLED,
          updatedById: userId
        }
      })
      return {
        data: updatedOrder
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw OrderNotFoundException
      }
      throw error
    }
  }
}
