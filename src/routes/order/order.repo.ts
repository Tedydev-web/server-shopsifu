import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'

// Types for better type safety
type CartItemWithDetails = {
  id: string
  quantity: number
  skuId: string
  userId: string
  sku: {
    id: string
    price: number
    stock: number
    image: string
    value: string
    updatedAt: Date
    createdById: string
    product: {
      id: string
      name: string
      deletedAt: Date | null
      publishedAt: Date | null
      brand: { id: string }
      categories: { id: string }[]
      productTranslations: {
        id: string
        name: string
        description: string
        languageId: string
      }[]
    }
  }
}

type DiscountWithIncludes = {
  id: string
  code: string
  name: string
  description: string | null
  value: number
  discountType: string
  discountApplyType: string
  discountStatus: string
  startDate: Date
  endDate: Date
  maxUses: number
  maxUsesPerUser: number | null
  usesCount: number
  usersUsed: string[]
  maxDiscountValue: number | null
  minOrderValue: number | null
  isPlatform: boolean
  voucherType: string
  displayType: string
  products: { id: string }[]
  categories: { id: string }[]
  brands: { id: string }[]
}

type DiscountSnapshotData = {
  name: string
  description: string
  discountType: string
  value: number
  code: string
  maxDiscountValue: number
  discountAmount: number
  minOrderValue: number
  isPlatform: boolean
  voucherType: string
  displayType: string
  discountApplyType: string
  targetInfo: any
  discountId: string
}
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
    shops: CreateOrderBodyType['shops'],
    platformDiscountCodes?: string[]
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
      const [paymentId, orders] = await this.createOrdersInTransaction(
        userId,
        shops,
        allBodyCartItemIds,
        platformDiscountCodes
      )
      return { paymentId, orders }
    } finally {
      await this.releaseLocks(locks)
    }
  }

  /**
   * Lấy SKU IDs từ cart items
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
   * Acquire locks cho SKUs
   */
  private async acquireSkuLocks(skuIds: string[]) {
    const redlock = this.configService.get('redis.redlock')
    return Promise.all(skuIds.map((skuId) => redlock.acquire([`lock:sku:${skuId}`], 3000)))
  }

  /**
   * Release locks
   */
  private async releaseLocks(locks: any[]) {
    await Promise.all(locks.map((lock) => lock.release().catch(() => {})))
  }

  /**
   * Tạo orders trong transaction
   */
  private async createOrdersInTransaction(
    userId: string,
    shops: CreateOrderBodyType['shops'],
    allBodyCartItemIds: string[],
    platformDiscountCodes?: string[]
  ): Promise<[number, CreateOrderResType['data']['orders']]> {
    return this.prismaService.$transaction(async (tx) => {
      // Lấy và validate cart items
      const cartItems = await this.getCartItemsWithDetails(tx, allBodyCartItemIds, userId)
      const cartItemMap = this.validateCartItems(cartItems, allBodyCartItemIds, shops)

      // Tạo payment
      const payment = await this.createPayment(tx)

      // Tạo orders với discounts
      const orders = await this.createOrdersWithDiscounts(
        tx,
        shops,
        cartItemMap,
        payment.id,
        userId,
        platformDiscountCodes
      )

      // Cleanup: xóa cart items và update stock
      await this.cleanupCartAndUpdateStock(tx, allBodyCartItemIds, cartItems)

      // Schedule payment cancellation job
      await this.orderProducer.addCancelPaymentJob(payment.id)

      return [payment.id, orders]
    })
  }

  /**
   * Lấy cart items với details
   */
  private async getCartItemsWithDetails(
    tx: any,
    cartItemIds: string[],
    userId: string
  ): Promise<CartItemWithDetails[]> {
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
   * Tạo payment
   */
  private async createPayment(tx: any) {
    return tx.payment.create({
      data: {
        status: PaymentStatus.PENDING
      }
    })
  }

  /**
   * Tạo orders với discount processing
   */
  private async createOrdersWithDiscounts(
    tx: any,
    shops: CreateOrderBodyType['shops'],
    cartItemMap: Map<string, any>,
    paymentId: number,
    userId: string,
    platformDiscountCodes?: string[] // ✅ Thêm platform discounts
  ): Promise<CreateOrderResType['data']['orders']> {
    const orders: CreateOrderResType['data']['orders'] = []

    // Xử lý platform discounts trước
    let platformDiscounts: any[] = []
    if (platformDiscountCodes && platformDiscountCodes.length > 0) {
      platformDiscounts = await this.getValidPlatformDiscountsForTransaction(tx, platformDiscountCodes, userId)
    }

    for (const item of shops) {
      const orderTotal = this.calculateOrderTotal(item.cartItemIds, cartItemMap)

      // Xử lý shop discounts
      const shopDiscounts = await this.processDiscountsForOrder(tx, item, cartItemMap, orderTotal, userId)

      // Xử lý platform discounts cho shop này (sẽ được phân bổ theo tỷ lệ)
      const platformDiscountsForShop = await this.processPlatformDiscountsForShop(
        tx,
        platformDiscounts,
        orderTotal,
        userId
      )

      const order = await this.createSingleOrder(tx, item, cartItemMap, paymentId, userId)

      // Tạo snapshots cho cả shop và platform discounts
      await this.createDiscountSnapshots(tx, [...shopDiscounts, ...platformDiscountsForShop], order.id)

      orders.push(order)
    }

    return orders
  }

  /**
   * Tính tổng giá trị order
   */
  private calculateOrderTotal(cartItemIds: string[], cartItemMap: Map<string, CartItemWithDetails>): number {
    return cartItemIds.reduce((sum, cartItemId) => {
      const cartItem = cartItemMap.get(cartItemId)!
      return sum + cartItem.sku.price * cartItem.quantity
    }, 0)
  }

  /**
   * Xử lý discounts cho một order - sử dụng validateDiscounts để tránh duplicate logic
   */
  private async processDiscountsForOrder(
    tx: any,
    orderItem: any,
    cartItemMap: Map<string, CartItemWithDetails>,
    orderTotal: number,
    userId: string
  ): Promise<DiscountSnapshotData[]> {
    if (!orderItem.discountCodes || orderItem.discountCodes.length === 0) {
      return []
    }

    // Sử dụng validateDiscounts method để get discount info
    const { discounts } = await this.getValidDiscountsForTransaction(tx, orderItem.discountCodes, userId)

    // Validate và apply discounts
    const appliedDiscounts: DiscountSnapshotData[] = []
    const { productIds, categoryIds, brandIds } = this.extractProductInfo(orderItem.cartItemIds, cartItemMap)

    for (const discount of discounts) {
      if (validateDiscountForOrder(discount, orderTotal, productIds, categoryIds, brandIds)) {
        const discountAmount = calculateDiscountAmount(discount, orderTotal)
        const targetInfo = this.prepareDiscountTargetInfo(discount)

        appliedDiscounts.push(prepareDiscountSnapshotData(discount, discountAmount, targetInfo))

        // Update discount usage
        await tx.discount.update({
          where: { id: discount.id },
          data: {
            usesCount: { increment: 1 },
            usersUsed: { push: userId }
          }
        })
      }
    }

    return appliedDiscounts
  }

  /**
   * Get valid discounts cho transaction (không duplicate validateDiscounts logic)
   */
  private async getValidDiscountsForTransaction(
    tx: any,
    discountCodes: string[],
    userId: string
  ): Promise<{ discounts: DiscountWithIncludes[] }> {
    const discounts = await tx.discount.findMany({
      where: {
        code: { in: discountCodes },
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

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher không tồn tại: ${missingCodes.join(', ')}`)
    }

    return { discounts }
  }

  /**
   * Get valid platform discounts cho transaction
   */
  private async getValidPlatformDiscountsForTransaction(
    tx: any,
    discountCodes: string[],
    userId: string
  ): Promise<DiscountWithIncludes[]> {
    const discounts = await tx.discount.findMany({
      where: {
        code: { in: discountCodes },
        discountStatus: DiscountStatus.ACTIVE,
        startDate: { lte: new Date() },
        endDate: { gte: new Date() },
        deletedAt: null,
        isPlatform: true // ✅ Chỉ lấy platform discounts
      },
      include: {
        products: { select: { id: true } },
        categories: { select: { id: true } },
        brands: { select: { id: true } }
      }
    })

    if (discounts.length !== discountCodes.length) {
      const foundCodes = discounts.map((d) => d.code)
      const missingCodes = discountCodes.filter((code) => !foundCodes.includes(code))
      throw new BadRequestException(`Mã voucher nền tảng không tồn tại: ${missingCodes.join(', ')}`)
    }

    return discounts
  }

  /**
   * Xử lý platform discounts cho một shop cụ thể
   */
  private async processPlatformDiscountsForShop(
    tx: any,
    platformDiscounts: DiscountWithIncludes[],
    shopOrderTotal: number,
    userId: string
  ): Promise<DiscountSnapshotData[]> {
    if (platformDiscounts.length === 0) {
      return []
    }

    const appliedPlatformDiscounts: DiscountSnapshotData[] = []

    for (const discount of platformDiscounts) {
      // Tính discount amount cho shop này
      const discountAmount = calculateDiscountAmount(discount, shopOrderTotal)

      // Chuẩn bị target info
      const targetInfo = this.prepareDiscountTargetInfo(discount)

      appliedPlatformDiscounts.push(prepareDiscountSnapshotData(discount, discountAmount, targetInfo))

      // Update discount usage
      await tx.discount.update({
        where: { id: discount.id },
        data: {
          usesCount: { increment: 1 },
          usersUsed: { push: userId }
        }
      })
    }

    return appliedPlatformDiscounts
  }

  /**
   * Extract product info từ cart items
   */
  private extractProductInfo(cartItemIds: string[], cartItemMap: Map<string, CartItemWithDetails>) {
    const productIds = cartItemIds.map((cartItemId) => {
      const cartItem = cartItemMap.get(cartItemId)!
      return cartItem.sku.product.id
    })

    const categoryIds = cartItemIds
      .map((cartItemId) => {
        const cartItem = cartItemMap.get(cartItemId)!
        return cartItem.sku.product.categories.map((c) => c.id)
      })
      .flat()
      .filter(Boolean)

    const brandIds = cartItemIds
      .map((cartItemId) => {
        const cartItem = cartItemMap.get(cartItemId)!
        return cartItem.sku.product.brand.id
      })
      .filter(Boolean)

    return { productIds, categoryIds, brandIds }
  }

  /**
   * Chuẩn bị discount target info
   */
  private prepareDiscountTargetInfo(discount: DiscountWithIncludes) {
    return discount.discountApplyType === DiscountApplyType.SPECIFIC
      ? {
          productIds: discount.products.map((p) => p.id),
          categoryIds: discount.categories.map((c) => c.id),
          brandIds: discount.brands.map((b) => b.id)
        }
      : null
  }

  /**
   * Tạo một order
   */
  private async createSingleOrder(
    tx: any,
    orderItem: any,
    cartItemMap: Map<string, CartItemWithDetails>,
    paymentId: number,
    userId: string
  ) {
    return tx.order.create({
      data: {
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
    })
  }

  /**
   * Tạo discount snapshots
   */
  private async createDiscountSnapshots(tx: any, appliedDiscounts: DiscountSnapshotData[], orderId: string) {
    for (const discountData of appliedDiscounts) {
      await tx.discountSnapshot.create({
        data: {
          ...discountData,
          orderId
        }
      })
    }
  }

  /**
   * Cleanup cart và update stock
   */
  private async cleanupCartAndUpdateStock(tx: any, cartItemIds: string[], cartItems: CartItemWithDetails[]) {
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
          if (isNotFoundPrismaError(e)) {
            throw VersionConflictException
          }
          throw e
        })
    }
  }

  /**
   * Validate và lấy discount info
   */
  async validateDiscounts(
    discountCodes: string[],
    userId: string
  ): Promise<{
    discounts: DiscountWithIncludes[]
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
    configFeeId?: string
    extraCostId?: string
    weight?: number
    length?: number
    width?: number
    height?: number
    shippingFee: number
    codAmount: number
    note?: string
    requiredNote?: string
    pickShift?: any
    status?: OrderShippingStatusType
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
        serviceId: data.serviceId,
        serviceTypeId: data.serviceTypeId,
        configFeeId: data.configFeeId,
        extraCostId: data.extraCostId,
        weight: data.weight,
        length: data.length,
        width: data.width,
        height: data.height,
        shippingFee: data.shippingFee,
        codAmount: data.codAmount,
        expectedDeliveryTime: null,
        trackingUrl: null,
        status: data.status,
        note: data.note,
        requiredNote: data.requiredNote,
        pickShift: data.pickShift,
        attempts: 0,
        lastError: null,
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
        toWardCode: data.toWardCode
      }
    })
  }

  /**
   * Cập nhật trạng thái OrderShipping
   */
  async updateOrderShippingStatus(orderId: string, status: OrderShippingStatusType) {
    return this.prismaService.orderShipping.update({
      where: { orderId },
      data: { status }
    })
  }

  /**
   * Lấy GHN order code từ order ID
   */
  async getGHNOrderCode(orderId: string): Promise<string | null> {
    const orderShipping = await this.prismaService.orderShipping.findUnique({
      where: { orderId },
      select: { orderCode: true, status: true }
    })

    // Chỉ trả về orderCode nếu shipping đã được tạo thành công
    if (orderShipping?.status === 'CREATED' && orderShipping.orderCode) {
      return orderShipping.orderCode
    }

    return null
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
    cartItems: CartItemWithDetails[],
    allBodyCartItemIds: string[],
    shops: CreateOrderBodyType['shops']
  ): Map<string, CartItemWithDetails> {
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
    const cartItemMap = new Map<string, CartItemWithDetails>()
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
}
