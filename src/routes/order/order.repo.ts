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
import {
  calculateDiscountAmount,
  isNotFoundPrismaError,
  validateDiscountForOrder,
  prepareDiscountSnapshotData
} from 'src/shared/helpers'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountApplyType, DiscountStatus } from 'src/shared/constants/discount.constant'
import { NotFoundRecordException } from 'src/shared/error'
import { BadRequestException } from '@nestjs/common'

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
                      productTranslations: true,
                      brand: true,
                      categories: true
                    }
                  }
                }
              }
            }
          })

          // Validate cart items
          const cartItemMap = this.validateCartItems(cartItems, allBodyCartItemIds, body)

          // 5. Tạo order và xóa cartItem trong transaction để đảm bảo tính toàn vẹn dữ liệu

          const payment = await tx.payment.create({
            data: {
              status: PaymentStatus.PENDING
            }
          })
          const orders: CreateOrderResType['data']['orders'] = []
          for (const item of body) {
            // Tính tổng giá trị đơn hàng trước khi áp dụng discount
            const ordertotalPayment = item.cartItemIds.reduce((sum, cartItemId) => {
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

              // Chuẩn bị dữ liệu để kiểm tra eligibility
              const productIds = item.cartItemIds.map((cartItemId) => {
                const cartItem = cartItemMap.get(cartItemId)!
                return cartItem.sku.product.id
              })
              const categoryIds = item.cartItemIds
                .map((cartItemId) => {
                  const cartItem = cartItemMap.get(cartItemId)!
                  return cartItem.sku.product.categories.map((c) => c.id)
                })
                .flat()
                .filter(Boolean)
              const brandIds = item.cartItemIds
                .map((cartItemId) => {
                  const cartItem = cartItemMap.get(cartItemId)!
                  return cartItem.sku.product.brand.id
                })
                .filter(Boolean)

              // Lọc và validate discounts
              const validDiscounts: typeof discounts = []
              for (const discount of discounts) {
                if (validateDiscountForOrder(discount, ordertotalPayment, productIds, categoryIds, brandIds)) {
                  validDiscounts.push(discount)
                }
              }

              // Tính toán giá trị giảm giá cho từng mã hợp lệ
              for (const discount of validDiscounts) {
                const discountAmount = calculateDiscountAmount(discount, ordertotalPayment)

                // Chuẩn bị dữ liệu để tạo DiscountSnapshot
                const targetInfo =
                  discount.discountApplyType === DiscountApplyType.SPECIFIC
                    ? {
                        productIds: discount.products.map((p) => p.id),
                        categoryIds: discount.categories.map((c) => c.id),
                        brandIds: discount.brands.map((b) => b.id)
                      }
                    : null

                appliedDiscountsToCreate.push(prepareDiscountSnapshotData(discount, discountAmount, targetInfo))

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

  /**
   * Validate và lấy discount info
   */
  async validateDiscounts(
    discountCodes: string[],
    userId: string
  ): Promise<{
    discounts: any[]
    userUsageMap: Map<string, number>
  }> {
    if (discountCodes.length === 0) {
      return {
        discounts: [],
        userUsageMap: new Map()
      }
    }

    // Lấy thông tin tất cả discounts một lần
    const discounts = await this.prismaService.discount.findMany({
      where: { code: { in: discountCodes } },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher không tồn tại: ${missingCodes.join(', ')}`)
    }

    // Lấy thông tin usage count một lần để tránh N+1 queries
    const userDiscountUsage = await this.prismaService.discountSnapshot.groupBy({
      by: ['discountId'],
      where: {
        discountId: { in: discounts.map((d) => d.id) },
        order: { userId }
      },
      _count: { discountId: true }
    })

    const userUsageMap = new Map(
      userDiscountUsage
        .filter((item) => item.discountId !== null)
        .map((item) => [item.discountId!, item._count.discountId])
    )

    return { discounts, userUsageMap }
  }

  /**
   * Lấy order shipping info
   */
  async getOrderShipping(orderId: string) {
    return this.prismaService.orderShipping.findUnique({
      where: { orderId }
    })
  }

  /**
   * Lấy shop info với address để tạo shipping
   */
  async getShopWithAddress(shopId: string) {
    const shopData = await this.prismaService.user.findUnique({
      where: { id: shopId }
    })

    if (!shopData) {
      throw NotFoundRecordException
    }

    // Lấy shop address từ UserAddress
    const shopUserAddress = await this.prismaService.userAddress.findFirst({
      where: { userId: shopId },
      include: { address: true }
    })

    if (!shopUserAddress || !shopUserAddress.address) {
      throw NotFoundRecordException
    }

    return {
      shop: shopData,
      address: shopUserAddress.address
    }
  }

  /**
   * Tạo OrderShipping record
   */
  async createOrderShipping(data: {
    orderId: string
    serviceId?: number
    serviceTypeId?: number
    shippingFee: number
    codAmount: number
    fromAddress: string
    fromName: string
    fromPhone: string
    fromProvinceName: string
    fromDistrictName: string
    fromWardName: string
    fromDistrictId: number
    fromWardCode: string
    toAddress: string
    toName: string
    toPhone: string
    toDistrictId: number
    toWardCode: string
  }) {
    return this.prismaService.orderShipping.create({
      data: {
        orderId: data.orderId,
        orderCode: 'TEMP_ORDER_CODE',
        serviceId: data.serviceId,
        serviceTypeId: data.serviceTypeId,
        shippingFee: data.shippingFee,
        codAmount: data.codAmount,
        expectedDeliveryTime: null,
        trackingUrl: null,
        status: 'PENDING',
        fromAddress: data.fromAddress,
        fromName: data.fromName,
        fromPhone: data.fromPhone,
        fromProvinceName: data.fromProvinceName,
        fromDistrictName: data.fromDistrictName,
        fromWardName: data.fromWardName,
        fromDistrictId: data.fromDistrictId,
        fromWardCode: data.fromWardCode,
        toAddress: data.toAddress,
        toName: data.toName,
        toPhone: data.toPhone,
        toDistrictId: data.toDistrictId,
        toWardCode: data.toWardCode,
        lastUpdatedAt: new Date()
      }
    })
  }

  async detail(userId: string, orderid: string): Promise<GetOrderDetailResType> {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderid,
        userId,
        deletedAt: null
      },
      include: {
        items: true,
        discounts: true
      }
    })
    if (!order) {
      throw OrderNotFoundException
    }

    // Tính toán giá trị cuối cùng
    const totalPayment = order.items.reduce((sum, item) => sum + item.skuPrice * item.quantity, 0)
    const totalVoucherDiscount = order.discounts.reduce((sum, discount) => sum + discount.discountAmount, 0)
    const totalOrderPayment = Math.max(0, totalPayment - totalVoucherDiscount)

    return {
      data: {
        ...order,
        totalItemCost: totalPayment,
        totalShippingFee: 0,
        totalVoucherDiscount: -totalVoucherDiscount,
        totalPayment: totalOrderPayment
      }
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

  /**
   * Validate cart items và trả về cartItemMap
   */
  private validateCartItems(
    cartItems: any[],
    allBodyCartItemIds: string[],
    body: CreateOrderBodyType
  ): Map<string, any> {
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
    const cartItemMap = new Map<string, any>()
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

    return cartItemMap
  }
}
