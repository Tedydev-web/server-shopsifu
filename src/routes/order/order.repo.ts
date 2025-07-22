import { Injectable } from '@nestjs/common'
import { OrderStatus, Prisma } from '@prisma/client'
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
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SharedDiscountRepo } from 'src/shared/repositories/shared-discount.repo'
import { DiscountHelperService } from 'src/shared/services/discount-helper.service'

@Injectable()
export class OrderRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private orderProducer: OrderProducer,
    private readonly configService: ConfigService,
    private readonly sharedDiscountRepo: SharedDiscountRepo,
    private readonly discountHelperService: DiscountHelperService
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
    paymentId: string
    orders: CreateOrderResType['data']['orders']
  }> {
    // 1. Kiểm tra xem tất cả cartItemIds có tồn tại trong cơ sở dữ liệu hay không
    // 2. Kiểm tra số lượng mua có lớn hơn số lượng tồn kho hay không
    // 3. Kiểm tra xem tất cả sản phẩm mua có sản phẩm nào bị xóa hay ẩn không
    // 4. Kiểm tra xem các skuId trong cartItem gửi lên có thuộc về shopid gửi lên không
    // 5. Tạo order
    // 6. Xóa cartItem
    const allBodyCartItemIds = body.map((item) => item.cartItemIds).flat()
    const allDiscountCodes = body.flatMap((item) => item.discountCodes || [])

    const [cartItemsForSKUId, discounts] = await Promise.all([
      this.prismaService.cartItem.findMany({
        where: { id: { in: allBodyCartItemIds }, userId },
        select: { skuId: true }
      }),
      this.prismaService.discount.findMany({
        where: { code: { in: allDiscountCodes }, deletedAt: null, status: 'ACTIVE' }
      })
    ])

    const skuIds = cartItemsForSKUId.map((cartItem) => cartItem.skuId)
    const redlock = this.configService.get('redis.redlock')
    const locks = await Promise.all(skuIds.map((skuId) => redlock.acquire([`lock:sku:${skuId}`], 3000)))

    try {
      const [paymentId, orders] = await this.prismaService.$transaction<[string, CreateOrderResType['data']['orders']]>(
        async (tx) => {
          const user = await tx.user.findUnique({ where: { id: userId } })
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
            const orderCartItems = cartItems.filter((ci) => item.cartItemIds.includes(ci.id))
            const orderValue = orderCartItems.reduce((sum, ci) => sum + ci.sku.price * ci.quantity, 0)
            const orderDiscounts = discounts.filter((d) => item.discountCodes?.includes(d.code))

            let totalDiscountAmount = 0
            const appliedDiscountsToCreate: any[] = []

            for (const discount of orderDiscounts) {
              const reason = await this.discountHelperService.checkDiscountAvailable({
                discount,
                orderValue,
                user,
                cart: orderCartItems.map((ci) => ({
                  productId: ci.sku.productId,
                  quantity: ci.quantity,
                  price: ci.sku.price,
                  shopId: ci.sku.createdById
                }))
              })

              if (!reason) {
                const discountAmount = this.discountHelperService.calculateDiscountAmount(discount, orderValue)
                totalDiscountAmount += discountAmount
                appliedDiscountsToCreate.push({
                  discountId: discount.id,
                  code: discount.code,
                  type: discount.type,
                  value: discount.value,
                  discountAmount
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
                  create: orderCartItems.map((cartItem) => ({
                    productName: cartItem.sku.product.name,
                    skuPrice: cartItem.sku.price,
                    image: cartItem.sku.image,
                    skuId: cartItem.sku.id,
                    skuValue: cartItem.sku.value,
                    quantity: cartItem.quantity,
                    productId: cartItem.sku.product.id,
                    productTranslations: cartItem.sku.product.productTranslations.map((t) => ({ ...t }))
                  }))
                },
                products: {
                  connect: orderCartItems.map((ci) => ({ id: ci.sku.product.id }))
                },
                appliedDiscounts: {
                  create: appliedDiscountsToCreate
                }
              }
            })
            orders.push(order)

            for (const appliedDiscount of appliedDiscountsToCreate) {
              await this.sharedDiscountRepo.applyUsage(appliedDiscount.discountId, userId)
            }
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
    return order
  }

  async cancel(userId: string, orderId: string): Promise<CancelOrderResType> {
    const order = await this.prismaService.order.findUnique({
      where: { id: orderId, userId, deletedAt: null },
      include: { appliedDiscounts: true }
    })

    if (!order) {
      throw OrderNotFoundException
    }
    if (order.status !== OrderStatus.PENDING_PAYMENT) {
      throw CannotCancelOrderException
    }

    await this.prismaService.$transaction(async (tx) => {
      for (const appliedDiscount of order.appliedDiscounts) {
        await this.sharedDiscountRepo.releaseUsage(appliedDiscount.discountId, userId)
      }

      await tx.order.update({
        where: { id: orderId },
        data: { status: OrderStatus.CANCELLED, updatedById: userId }
      })
    })

    const updatedOrder = await this.detail(userId, orderId)
    return { data: updatedOrder }
  }
}
