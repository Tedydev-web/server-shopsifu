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
import { SharedShippingRepository } from 'src/shared/repositories/shared-shipping.repo'

@Injectable()
export class OrderRepo {
  private readonly logger = new Logger(OrderRepo.name)

  constructor(
    private readonly prismaService: PrismaService,
    private orderProducer: OrderProducer, // TODO: Move to OrderService - business orchestration
    private readonly configService: ConfigService, // TODO: Move lock logic to OrderService
    private readonly sharedShippingRepo: SharedShippingRepository
  ) {}

  // ============================================================
  // CORE CRUD METHODS - Repository Pattern Compliant
  // ============================================================

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
        items: true,
        discounts: true, // Thêm discounts để lấy voucher discount
        shipping: {
          select: {
            orderCode: true
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

    // Map orderCode từ shipping vào order và loại bỏ shipping object
    const ordersWithOrderCode = data.map((order) => {
      const { shipping, ...orderWithoutShipping } = order
      return {
        ...orderWithoutShipping,
        orderCode: shipping?.orderCode || null,
        totalItemCost: 0,
        totalShippingFee: 0,
        totalVoucherDiscount: 0,
        totalPayment: 0
      }
    })

    return {
      data: ordersWithOrderCode,
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
    // Chuẩn bị dữ liệu ban đầu
    const allBodyCartItemIds = shops.map((item) => item.cartItemIds).flat()
    const skuIds = await this.getSkuIdsFromCartItems(allBodyCartItemIds, userId)

    // Acquire locks cho tất cả SKUs
    const locks = await this.acquireSkuLocks(skuIds)

    try {
      const [paymentId, orders] = await this.createOrdersInTransaction(userId, shops, allBodyCartItemIds)
      return { paymentId, orders }
    } finally {
      await this.releaseLocks(locks)
    }
  }

  // ============================================================
  // BUSINESS LOGIC METHODS - Should be moved to OrderService
  // TODO: Refactor to move business orchestration to Service layer
  // ============================================================

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
   * TODO: Move lock management to OrderService - business orchestration concern
   */
  private async acquireSkuLocks(skuIds: string[]) {
    const redlock = this.configService.get('redis.redlock')
    return Promise.all(skuIds.map((skuId) => redlock.acquire([`lock:sku:${skuId}`], 3000)))
  }

  /**
   * Release locks - Core business logic
   * TODO: Move lock management to OrderService - business orchestration concern
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
    return this.prismaService.$transaction(async (tx) => {
      // Lấy và validate cart items
      const cartItems = await this.getCartItemsWithDetails(tx, allBodyCartItemIds, userId)
      const cartItemMap = this.validateCartItems(cartItems, allBodyCartItemIds, shops)

      // Tạo payment
      const payment = await this.createPayment(tx)

      // Tạo orders (đơn giản, không có discount logic)
      const orders = await this.createSimpleOrders(tx, shops, cartItemMap, payment.id, userId)

      // Cleanup: xóa cart items và update stock
      await this.cleanupCartAndUpdateStock(tx, allBodyCartItemIds, cartItems)

      // Schedule payment cancellation job
      // TODO: Move queue scheduling to OrderService - business orchestration concern
      await this.orderProducer.addCancelPaymentJob(payment.id)

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
    const orders: CreateOrderResType['data']['orders'] = []

    for (const item of shops) {
      const order = await this.createSingleOrder(tx, item, cartItemMap, paymentId, userId)
      orders.push(order)
    }

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

    return tx.order.create({ data: orderData })
  }

  /**
   * Cleanup cart và update stock - Core business logic
   */
  private async cleanupCartAndUpdateStock(tx: any, cartItemIds: string[], cartItems: any[]) {
    // Xóa cart items
    await tx.cartItem.deleteMany({
      where: {
        id: { in: cartItemIds }
      }
    })

    // Update stock cho từng item
    for (const item of cartItems) {
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
    }
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
        items: true,
        shipping: {
          select: { orderCode: true }
        }
      }
    })
    if (!order) {
      throw OrderNotFoundException
    }

    // Tính toán giá trị cơ bản (không có shipping/discount)
    const totalPayment = (order.items || []).reduce((sum, item) => sum + (item.skuPrice || 0) * (item.quantity || 0), 0)

    return {
      data: {
        ...order,
        orderCode: order.shipping?.orderCode || null,
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
  async listByShop(
    shopId: string,
    query: {
      page: number
      limit: number
      status?: OrderStatusType
      startDate?: string
      endDate?: string
      customerName?: string
      orderCode?: string
    }
  ): Promise<any> {
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

    // Lấy list order với thông tin user và shipping
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
        },
        shipping: {
          select: {
            orderCode: true
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
    const totalPages = Math.ceil(totalItems / limit)

    // Map orderCode từ shipping vào order và loại bỏ shipping object
    const ordersWithOrderCode = data.map((order) => {
      const { shipping, ...orderWithoutShipping } = order
      return {
        ...orderWithoutShipping,
        orderCode: shipping?.orderCode || null
      }
    })

    return {
      data: ordersWithOrderCode,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    }
  }

  /**
   * Lấy danh sách orders cho admin (có thể xem tất cả orders)
   */
  async listForAdmin(query: {
    page: number
    limit: number
    status?: OrderStatusType
    startDate?: string
    endDate?: string
    customerName?: string
    orderCode?: string
  }): Promise<any> {
    const { page, limit, status, startDate, endDate, customerName, orderCode } = query
    const skip = (page - 1) * limit
    const take = limit

    const where: Prisma.OrderWhereInput = {
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

    // Lấy list order với thông tin user và shipping
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
        },
        shipping: {
          select: {
            orderCode: true
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
    const totalPages = Math.ceil(totalItems / limit)

    // Tính toán pricing cho từng order (tương tự như method list())
    const ordersWithPricing = await Promise.all(
      data.map(async (order) => {
        try {
          // Lấy shipping info để tính pricing
          const orderShipping = await this.prismaService.orderShipping.findUnique({
            where: { orderId: order.id },
            select: { shippingFee: true, codAmount: true }
          })

          // Tính toán giá trực tiếp từ order items
          const totalItemCost = (order.items || []).reduce((sum, item) => {
            return sum + (item.skuPrice || 0) * (item.quantity || 0)
          }, 0)

          const totalShippingFee = orderShipping?.shippingFee || 0

          // Tính totalVoucherDiscount từ pricing logic
          let totalVoucherDiscount = 0
          if (orderShipping && orderShipping.codAmount && orderShipping.codAmount > 0) {
            // Với COD orders: totalPayment = codAmount
            const expectedTotalPayment = orderShipping.codAmount
            const calculatedVoucherDiscount = totalItemCost + totalShippingFee - expectedTotalPayment

            // Chỉ áp dụng nếu voucher discount hợp lý (> 0 và < totalItemCost)
            if (calculatedVoucherDiscount > 0 && calculatedVoucherDiscount < totalItemCost) {
              totalVoucherDiscount = calculatedVoucherDiscount
            }
          }

          const totalPayment = totalItemCost + totalShippingFee - totalVoucherDiscount

          return {
            ...order,
            orderCode: order.shipping?.orderCode || null,
            totalItemCost,
            totalShippingFee,
            totalVoucherDiscount,
            totalPayment
          }
        } catch (error) {
          // Nếu có lỗi, trả về với giá trị mặc định
          const totalItemCost = (order.items || []).reduce((sum, item) => {
            return sum + (item.skuPrice || 0) * (item.quantity || 0)
          }, 0)

          return {
            ...order,
            orderCode: order.shipping?.orderCode || null,
            totalItemCost,
            totalShippingFee: 0,
            totalVoucherDiscount: 0,
            totalPayment: totalItemCost
          }
        }
      })
    )

    return {
      data: ordersWithPricing,
      metadata: {
        totalItems,
        page,
        limit,
        totalPages,
        hasNext: page < totalPages,
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
        },
        shipping: {
          select: {
            orderCode: true
          }
        }
      }
    })

    if (!order) {
      return null
    }

    // Tính toán giá trị cơ bản
    const totalPayment = (order.items || []).reduce((sum, item) => sum + (item.skuPrice || 0) * (item.quantity || 0), 0)

    return {
      data: {
        ...order,
        orderCode: order.shipping?.orderCode || null,
        totalItemCost: totalPayment,
        totalShippingFee: 0,
        totalVoucherDiscount: 0,
        totalPayment: totalPayment
      }
    }
  }

  /**
   * Lấy chi tiết order cho admin (có thể xem tất cả orders)
   */
  async detailForAdmin(orderId: string): Promise<any> {
    const order = await this.prismaService.order.findUnique({
      where: {
        id: orderId,
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
        },
        shipping: {
          select: {
            orderCode: true
          }
        }
      }
    })

    if (!order) {
      return null
    }

    // Tính toán giá trị cơ bản
    const totalItemCost = (order.items || []).reduce(
      (sum, item) => sum + (item.skuPrice || 0) * (item.quantity || 0),
      0
    )

    // Lấy shipping info để tính pricing đầy đủ
    const orderShipping = await this.prismaService.orderShipping.findUnique({
      where: { orderId },
      select: { shippingFee: true, codAmount: true }
    })

    // Tính totalVoucherDiscount từ pricing logic
    let totalVoucherDiscount = 0
    let totalShippingFee = 0
    let totalPayment = totalItemCost

    if (orderShipping) {
      totalShippingFee = orderShipping.shippingFee || 0

      // Với COD orders: totalPayment = codAmount
      if (orderShipping.codAmount && orderShipping.codAmount > 0) {
        const expectedTotalPayment = orderShipping.codAmount
        const calculatedVoucherDiscount = totalItemCost + totalShippingFee - expectedTotalPayment

        // Chỉ áp dụng nếu voucher discount hợp lý (> 0 và < totalItemCost)
        if (calculatedVoucherDiscount > 0 && calculatedVoucherDiscount < totalItemCost) {
          totalVoucherDiscount = calculatedVoucherDiscount
        }
      }

      // Tính lại totalPayment với voucher discount đã được tính
      totalPayment = totalItemCost + totalShippingFee - totalVoucherDiscount
    }

    return {
      data: {
        ...order,
        orderCode: order.shipping?.orderCode || null,
        totalItemCost,
        totalShippingFee,
        totalVoucherDiscount,
        totalPayment
      }
    }
  }

  /**
   * Hủy order - Core CRUD
   */
  async cancel(userId: string, orderId: string): Promise<CancelOrderResType> {
    this.logger.log(`[ORDER_REPO] Bắt đầu hủy order: ${orderId} cho user: ${userId}`)

    try {
      this.logger.log(`[ORDER_REPO] Tìm order trong database...`)
      const order = await this.prismaService.order.findUniqueOrThrow({
        where: {
          id: orderId,
          userId,
          deletedAt: null
        }
      })

      this.logger.log(`[ORDER_REPO] Order found: ${JSON.stringify(order, null, 2)}`)
      this.logger.log(`[ORDER_REPO] Order status: ${order.status}`)

      // Kiểm tra xem status hiện tại có thể hủy được không
      const cancellableStatuses: OrderStatusType[] = [
        OrderStatus.PENDING_PAYMENT,
        OrderStatus.PENDING_PACKAGING,
        OrderStatus.PICKUPED,
        OrderStatus.PENDING_DELIVERY
      ]

      if (!cancellableStatuses.includes(order.status as OrderStatusType)) {
        this.logger.warn(`[ORDER_REPO] Không thể hủy order với status: ${order.status}`)
        throw CannotCancelOrderException
      }

      // Kiểm tra xem order đã có GHN order chưa
      this.logger.log(`[ORDER_REPO] Kiểm tra OrderShipping cho order: ${orderId}`)
      const orderShipping = await this.prismaService.orderShipping.findUnique({
        where: { orderId },
        select: { orderCode: true, status: true }
      })

      this.logger.log(`[ORDER_REPO] OrderShipping found: ${JSON.stringify(orderShipping, null, 2)}`)

      // Nếu có GHN order, cần hủy trên GHN system trước
      if (orderShipping?.orderCode && orderShipping.status === 'CREATED') {
        try {
          // Hủy đơn hàng GHN
          const cancelResult = await this.sharedShippingRepo.cancelGHNOrderForOrder(orderId)
          this.logger.log(`[ORDER_REPO] Kết quả hủy đơn hàng GHN: ${JSON.stringify(cancelResult, null, 2)}`)

          // Update OrderShipping status thành FAILED
          await this.sharedShippingRepo.updateOrderShippingStatusForCancellation(
            orderId,
            'FAILED',
            'Order cancelled by user - GHN order cancelled'
          )
        } catch (error) {
          this.logger.error(`[ORDER_REPO] Lỗi khi xử lý OrderShipping: ${error.message}`)
          // Tiếp tục hủy local order ngay cả khi có lỗi
        }
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

      // Thêm orderCode vào response
      const orderWithOrderCode = {
        ...updatedOrder,
        orderCode: orderShipping?.orderCode || null
      }

      return {
        data: orderWithOrderCode
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
   * TODO: Move complex business validation to OrderService
   * Repository should focus on data access, not business rules
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

    const isValidShop = shops.every((item) =>
      item.cartItemIds.every((cartItemId) => {
        const cartItem = cartItemMap.get(cartItemId)!
        return item.shopId === cartItem.sku.createdById
      })
    )

    if (!isValidShop) {
      throw SKUNotBelongToShopException
    }

    return cartItemMap
  }

  /**
   * Cập nhật trạng thái nhiều orders cùng lúc
   */
  async updateMultipleOrdersStatus(orderIds: string[], status: OrderStatusType) {
    return this.prismaService.order.updateMany({
      where: {
        id: { in: orderIds },
        deletedAt: null
      },
      data: {
        status
      }
    })
  }
}
