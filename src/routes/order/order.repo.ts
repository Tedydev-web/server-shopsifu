import { Injectable, Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { OrderStatus, OrderStatusType } from 'src/shared/constants/order.constant'
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
import { OrderProducer } from 'src/shared/queue/producer/order.producer'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { VersionConflictException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class OrderRepo {
  private readonly logger = new Logger(OrderRepo.name)

  constructor(
    private readonly prismaService: PrismaService,
    private orderProducer: OrderProducer,
    private readonly configService: ConfigService
  ) {}

  /**
   * Lấy danh sách orders - Core CRUD (cho User xem đơn hàng của mình)
   */
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

  /**
   * Tạo order - Core CRUD (đơn giản, không có discount/shipping logic)
   */
  async create(
    userId: string,
    shops: CreateOrderBodyType['shops']
  ): Promise<{
    paymentId: number
    orders: CreateOrderResType['data']['orders']
  }> {
    this.logger.log(`[ORDER_REPO] Bắt đầu tạo orders cho user: ${userId}`)
    this.logger.log(`[ORDER_REPO] Số lượng shops: ${shops.length}`)

    // Chuẩn bị dữ liệu ban đầu
    const allBodyCartItemIds = shops.map((item) => item.cartItemIds).flat()
    this.logger.log(`[ORDER_REPO] Tổng số cart item IDs: ${allBodyCartItemIds.length}`)
    this.logger.log(`[ORDER_REPO] Cart item IDs: ${JSON.stringify(allBodyCartItemIds)}`)

    const skuIds = await this.getSkuIdsFromCartItems(allBodyCartItemIds, userId)
    this.logger.log(`[ORDER_REPO] SKU IDs từ cart items: ${JSON.stringify(skuIds)}`)

    // Acquire locks cho tất cả SKUs
    this.logger.log(`[ORDER_REPO] Bắt đầu acquire locks cho ${skuIds.length} SKUs`)
    const locks = await this.acquireSkuLocks(skuIds)
    this.logger.log(`[ORDER_REPO] Đã acquire ${locks.length} locks thành công`)

    try {
      this.logger.log(`[ORDER_REPO] Bắt đầu tạo orders trong transaction`)
      const [paymentId, orders] = await this.createOrdersInTransaction(userId, shops, allBodyCartItemIds)
      this.logger.log(`[ORDER_REPO] Transaction hoàn thành - paymentId: ${paymentId}, orders: ${orders.length}`)
      return { paymentId, orders }
    } finally {
      this.logger.log(`[ORDER_REPO] Bắt đầu release ${locks.length} locks`)
      await this.releaseLocks(locks)
      this.logger.log(`[ORDER_REPO] Đã release tất cả locks`)
    }
  }

  /**
   * Lấy SKU IDs từ cart items - Core business logic
   */
  private async getSkuIdsFromCartItems(cartItemIds: string[], userId: string): Promise<string[]> {
    const cartItemsForSKUId = await this.prismaService.cartItem.findMany({
      where: {
        id: { in: cartItemIds },
        userId
      },
      select: { skuId: true }
    })
    return cartItemsForSKUId.map((cartItem) => cartItem.skuId)
  }

  /**
   * Acquire locks cho SKUs - Core business logic
   */
  private async acquireSkuLocks(skuIds: string[]) {
    const redlock = this.configService.get('redis.redlock')
    return Promise.all(skuIds.map((skuId) => redlock.acquire([`lock:sku:${skuId}`], 3000)))
  }

  /**
   * Release locks - Core business logic
   */
  private async releaseLocks(locks: any[]) {
    await Promise.all(locks.map((lock) => lock.release().catch(() => {})))
  }

  /**
   * Tạo orders trong transaction - Core business logic
   */
  private async createOrdersInTransaction(
    userId: string,
    shops: CreateOrderBodyType['shops'],
    allBodyCartItemIds: string[]
  ): Promise<[number, CreateOrderResType['data']['orders']]> {
    this.logger.log(`[ORDER_REPO] Bắt đầu transaction tạo orders`)

    return this.prismaService.$transaction(async (tx) => {
      this.logger.log(`[ORDER_REPO] Transaction started`)

      // Lấy và validate cart items
      this.logger.log(`[ORDER_REPO] Lấy cart items với details`)
      const cartItems = await this.getCartItemsWithDetails(tx, allBodyCartItemIds, userId)
      this.logger.log(`[ORDER_REPO] Lấy được ${cartItems.length} cart items`)

      this.logger.log(`[ORDER_REPO] Bắt đầu validate cart items`)
      const cartItemMap = this.validateCartItems(cartItems, allBodyCartItemIds, shops)
      this.logger.log(`[ORDER_REPO] Cart items validated thành công, map size: ${cartItemMap.size}`)

      // Tạo payment
      this.logger.log(`[ORDER_REPO] Bắt đầu tạo payment`)
      const payment = await this.createPayment(tx)
      this.logger.log(`[ORDER_REPO] Payment created: ${JSON.stringify(payment)}`)

      // Tạo orders (đơn giản, không có discount logic)
      this.logger.log(`[ORDER_REPO] Bắt đầu tạo ${shops.length} orders`)
      const orders = await this.createSimpleOrders(tx, shops, cartItemMap, payment.id, userId)
      this.logger.log(`[ORDER_REPO] Orders created: ${orders.length} orders`)

      // Cleanup: xóa cart items và update stock
      this.logger.log(`[ORDER_REPO] Bắt đầu cleanup cart và update stock`)
      await this.cleanupCartAndUpdateStock(tx, allBodyCartItemIds, cartItems)
      this.logger.log(`[ORDER_REPO] Cleanup hoàn thành`)

      // Schedule payment cancellation job
      this.logger.log(`[ORDER_REPO] Bắt đầu schedule payment cancellation job cho paymentId: ${payment.id}`)
      await this.orderProducer.addCancelPaymentJob(payment.id)
      this.logger.log(`[ORDER_REPO] Payment cancellation job đã được schedule`)

      this.logger.log(`[ORDER_REPO] Transaction hoàn thành thành công`)
      return [payment.id, orders]
    })
  }

  /**
   * Lấy cart items với details - Core business logic
   */
  private async getCartItemsWithDetails(tx: any, cartItemIds: string[], userId: string): Promise<any[]> {
    return tx.cartItem.findMany({
      where: {
        id: { in: cartItemIds },
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
  }

  /**
   * Tạo payment - Core business logic
   */
  private async createPayment(tx: any) {
    return tx.payment.create({
      data: {
        status: PaymentStatus.PENDING
      }
    })
  }

  /**
   * Tạo orders đơn giản (không có discount logic) - Core business logic
   */
  private async createSimpleOrders(
    tx: any,
    shops: CreateOrderBodyType['shops'],
    cartItemMap: Map<string, any>,
    paymentId: number,
    userId: string
  ): Promise<CreateOrderResType['data']['orders']> {
    this.logger.log(`[ORDER_REPO] Bắt đầu tạo ${shops.length} simple orders`)
    const orders: CreateOrderResType['data']['orders'] = []

    for (const [index, item] of shops.entries()) {
      this.logger.log(`[ORDER_REPO] Tạo order ${index + 1}/${shops.length} cho shop: ${item.shopId}`)
      const order = await this.createSingleOrder(tx, item, cartItemMap, paymentId, userId)
      this.logger.log(`[ORDER_REPO] Order ${index + 1} created: ${JSON.stringify(order)}`)
      orders.push(order)
    }

    this.logger.log(`[ORDER_REPO] Tất cả ${orders.length} orders đã được tạo`)
    return orders
  }

  /**
   * Tạo một order - Core business logic
   */
  private async createSingleOrder(
    tx: any,
    orderItem: any,
    cartItemMap: Map<string, any>,
    paymentId: number,
    userId: string
  ) {
    this.logger.log(
      `[ORDER_REPO] Tạo single order cho shop: ${orderItem.shopId}, cartItems: ${orderItem.cartItemIds.length}`
    )

    const orderData = {
      userId,
      status: OrderStatus.PENDING_PAYMENT,
      receiver: orderItem.receiver,
      createdById: userId,
      shopId: orderItem.shopId,
      paymentId,
      items: {
        create: orderItem.cartItemIds.map((cartItemId: string) => {
          const cartItem = cartItemMap.get(cartItemId)!
          return {
            productName: cartItem.sku.product.name,
            skuPrice: cartItem.sku.price,
            image: cartItem.sku.image,
            skuId: cartItem.sku.id,
            skuValue: cartItem.sku.value,
            quantity: cartItem.quantity,
            productId: cartItem.sku.product.id,
            productTranslations: cartItem.sku.product.productTranslations.map((translation) => ({
              id: translation.id,
              name: translation.name,
              description: translation.description,
              languageId: translation.languageId
            }))
          }
        })
      },
      products: {
        connect: orderItem.cartItemIds.map((cartItemId: string) => {
          const cartItem = cartItemMap.get(cartItemId)!
          return { id: cartItem.sku.product.id }
        })
      }
    }

    this.logger.log(`[ORDER_REPO] Order data: ${JSON.stringify(orderData, null, 2)}`)

    const order = await tx.order.create({ data: orderData })
    this.logger.log(`[ORDER_REPO] Order created successfully: ${order.id}`)

    return order
  }

  /**
   * Cleanup cart và update stock - Core business logic
   */
  private async cleanupCartAndUpdateStock(tx: any, cartItemIds: string[], cartItems: any[]) {
    this.logger.log(`[ORDER_REPO] Bắt đầu cleanup cho ${cartItemIds.length} cart items`)

    // Xóa cart items
    this.logger.log(`[ORDER_REPO] Xóa ${cartItemIds.length} cart items`)
    await tx.cartItem.deleteMany({
      where: {
        id: { in: cartItemIds }
      }
    })
    this.logger.log(`[ORDER_REPO] Cart items đã được xóa`)

    // Update stock cho từng item
    this.logger.log(`[ORDER_REPO] Bắt đầu update stock cho ${cartItems.length} items`)
    for (const [index, item] of cartItems.entries()) {
      this.logger.log(
        `[ORDER_REPO] Update stock item ${index + 1}/${cartItems.length}: SKU ${item.sku.id}, quantity: ${item.quantity}, current stock: ${item.sku.stock}`
      )

      await tx.sKU
        .update({
          where: {
            id: item.sku.id,
            updatedAt: item.sku.updatedAt,
            stock: { gte: item.quantity }
          },
          data: {
            stock: { decrement: item.quantity }
          }
        })
        .catch((e) => {
          this.logger.error(`[ORDER_REPO] Lỗi update stock cho SKU ${item.sku.id}: ${e.message}`)
          if (isNotFoundPrismaError(e)) {
            throw VersionConflictException
          }
          throw e
        })

      this.logger.log(`[ORDER_REPO] Stock updated thành công cho SKU ${item.sku.id}`)
    }

    this.logger.log(`[ORDER_REPO] Cleanup và update stock hoàn thành`)
  }

  /**
   * Lấy chi tiết order - Core CRUD (cho User xem đơn hàng của mình)
   */
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

    // Tính toán giá trị cơ bản (không có shipping/discount)
    const totalPayment = order.items.reduce((sum, item) => sum + item.skuPrice * item.quantity, 0)

    return {
      data: {
        ...order,
        totalItemCost: totalPayment,
        totalShippingFee: 0,
        totalVoucherDiscount: 0,
        totalPayment: totalPayment
      }
    }
  }

  /**
   * Lấy danh sách orders theo shop (cho Seller xem đơn hàng của shop mình)
   */
  async listByShop(shopId: string, query: any): Promise<any> {
    const { page, limit, status, startDate, endDate, customerName, orderCode } = query
    const skip = (page - 1) * limit
    const take = limit

    const where: Prisma.OrderWhereInput = {
      shopId,
      deletedAt: null,
      status
    }

    // Filter theo ngày
    if (startDate || endDate) {
      where.createdAt = {}
      if (startDate) where.createdAt.gte = new Date(startDate)
      if (endDate) where.createdAt.lte = new Date(endDate)
    }

    // Filter theo tên khách hàng
    if (customerName) {
      where.user = {
        name: {
          contains: customerName,
          mode: 'insensitive'
        }
      }
    }

    // Filter theo mã đơn hàng
    if (orderCode) {
      where.id = {
        contains: orderCode,
        mode: 'insensitive'
      }
    }

    // Đếm tổng số order
    const totalItem$ = this.prismaService.order.count({
      where
    })

    // Lấy list order với thông tin user
    const data$ = await this.prismaService.order.findMany({
      where,
      include: {
        items: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            phoneNumber: true
          }
        }
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

  /**
   * Lấy chi tiết order theo shop (cho Seller xem đơn hàng của shop mình)
   */
  async detailByShop(shopId: string, orderId: string): Promise<any> {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderId,
        shopId,
        deletedAt: null
      },
      include: {
        items: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            phoneNumber: true
          }
        }
      }
    })

    if (!order) {
      return null
    }

    // Tính toán giá trị cơ bản
    const totalPayment = order.items.reduce((sum, item) => sum + item.skuPrice * item.quantity, 0)

    return {
      data: {
        ...order,
        totalItemCost: totalPayment,
        totalShippingFee: 0,
        totalVoucherDiscount: 0,
        totalPayment: totalPayment
      }
    }
  }

  /**
   * Cập nhật trạng thái đơn hàng của shop
   */
  async updateOrderStatus(shopId: string, orderId: string, status: OrderStatusType, updatedById: string) {
    return this.prismaService.order.update({
      where: {
        id: orderId,
        shopId,
        deletedAt: null
      },
      data: {
        status,
        updatedById,
        updatedAt: new Date()
      }
    })
  }

  /**
   * Hủy order - Core CRUD
   */
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
   * Validate cart items và trả về cartItemMap - Core business logic
   */
  private validateCartItems(
    cartItems: any[],
    allBodyCartItemIds: string[],
    shops: CreateOrderBodyType['shops']
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
    const isValidShop = shops.every((item) => {
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

  /**
   * Cập nhật trạng thái nhiều orders cùng lúc
   */
  async updateMultipleOrdersStatus(orderIds: string[], status: string) {
    return this.prismaService.order.updateMany({
      where: {
        id: { in: orderIds },
        deletedAt: null
      },
      data: {
        status: status as any
      }
    })
  }
}
