import { Injectable, BadRequestException, Logger } from '@nestjs/common'
import { OrderStatus, OrderStatusType } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaymentProducer } from '../queue/producer/payment.producer'
import { ShippingProducer } from '../queue/producer/shipping.producer'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus, OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'
import { CreateOrderType } from 'src/routes/shipping/ghn/shipping-ghn.model'

// Constants để tránh magic numbers
const SHIPPING_DEFAULTS = {
  WEIGHT: 1000,
  LENGTH: 30,
  WIDTH: 20,
  HEIGHT: 15
} as const

const PAYMENT_ID_PREFIX = 'SSPX'

@Injectable()
export class SharedPaymentRepository {
  private readonly logger = new Logger(SharedPaymentRepository.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer,
    private readonly shippingProducer: ShippingProducer
  ) {}

  /**
   * Tạo GHN orders cho online payment sau khi thanh toán thành công
   */
  private async createGHNOrdersForOnlinePayment(orders: Array<{ id: string }>): Promise<void> {
    this.logger.log(`[SHARED_PAYMENT] Bắt đầu tạo GHN orders cho ${orders.length} orders`)

    try {
      for (const order of orders) {
        this.logger.log(`[SHARED_PAYMENT] Xử lý order: ${order.id}`)

        try {
          // 1. Lấy order details với đầy đủ thông tin
          const orderDetails = (await this.prismaService.order.findUnique({
            where: { id: order.id },
            include: {
              items: {
                include: {
                  sku: {
                    include: {
                      product: true
                    }
                  }
                }
              },
              shop: {
                include: {
                  UserAddress: {
                    where: { isDefault: true },
                    take: 1,
                    include: {
                      address: true
                    }
                  }
                }
              }
            }
          })) as any

          if (!orderDetails) {
            this.logger.error(`[SHARED_PAYMENT] Không tìm thấy order: ${order.id}`)
            continue
          }

          this.logger.log(
            `[SHARED_PAYMENT] Order details loaded: shopId=${orderDetails.shopId}, items=${orderDetails.items.length}`
          )

          // 2. Lấy OrderShipping record
          const orderShipping = await this.prismaService.orderShipping.findFirst({
            where: { orderId: order.id }
          })

          if (!orderShipping) {
            this.logger.error(`[SHARED_PAYMENT] Không tìm thấy OrderShipping cho order: ${order.id}`)
            continue
          }

          this.logger.log(
            `[SHARED_PAYMENT] OrderShipping found: serviceId=${orderShipping.serviceId}, status=${orderShipping.status}`
          )

          // 3. Validate shop address
          if (!orderDetails.shop?.UserAddress || orderDetails.shop.UserAddress.length === 0) {
            this.logger.error(`[SHARED_PAYMENT] Shop ${orderDetails.shopId} không có địa chỉ mặc định`)
            continue
          }

          const shopAddress = orderDetails.shop.UserAddress[0].address
          this.logger.log(
            `[SHARED_PAYMENT] Shop address: ${shopAddress.province}, ${shopAddress.district}, ${shopAddress.ward}`
          )

          // 4. Chuẩn bị shipping job data
          const shippingJobData: CreateOrderType = {
            from_address: orderShipping.fromAddress || '',
            from_name: orderShipping.fromName || '',
            from_phone: orderShipping.fromPhone || '',
            from_province_name: orderShipping.fromProvinceName || '',
            from_district_name: orderShipping.fromDistrictName || '',
            from_ward_name: orderShipping.fromWardName || '',
            to_name: orderShipping.toName || '',
            to_phone: orderShipping.toPhone || '',
            to_address: orderShipping.toAddress || '',
            to_ward_code: orderShipping.toWardCode || '',
            to_district_id: orderShipping.toDistrictId || 0,
            client_order_code: `SSPX${order.id}`,
            cod_amount: orderShipping.codAmount || 0,
            shippingFee: orderShipping.shippingFee || 0,
            weight: orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT,
            length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
            width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
            height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT,
            service_id: orderShipping.serviceId || 0,
            service_type_id: orderShipping.serviceTypeId || 0,
            coupon: null,
            items: orderDetails.items.map((item) => ({
              name: `Item ${item.sku?.product?.name?.substring(0, 50) || 'UNKNOWN'}`, // Limit name length
              quantity: item.quantity,
              weight: Math.ceil((orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT) / orderDetails.items.length), // Distribute weight
              length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
              width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
              height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT
            })),
            payment_type_id: 1, // Online payment
            note: 'Online payment completed',
            required_note: orderShipping.requiredNote || 'CHOTHUHANG'
          }

          this.logger.log(
            `[SHARED_PAYMENT] Shipping job data prepared cho order ${order.id}: ${JSON.stringify(shippingJobData, null, 2)}`
          )

          // 5. Enqueue shipping job
          await this.shippingProducer.enqueueCreateOrder(shippingJobData)
          this.logger.log(`[SHARED_PAYMENT] Shipping job enqueued thành công cho order: ${order.id}`)

          // 6. Update OrderShipping status to ENQUEUED
          await this.prismaService.orderShipping.update({
            where: { id: orderShipping.id },
            data: {
              status: OrderShippingStatus.ENQUEUED,
              lastUpdatedAt: new Date()
            }
          })
          this.logger.log(`[SHARED_PAYMENT] OrderShipping status updated to ENQUEUED cho order: ${order.id}`)
        } catch (orderError) {
          this.logger.error(`[SHARED_PAYMENT] Lỗi khi xử lý order ${order.id}: ${orderError.message}`, orderError.stack)

          // Update OrderShipping status to FAILED
          try {
            const orderShipping = await this.prismaService.orderShipping.findFirst({
              where: { orderId: order.id }
            })

            if (orderShipping) {
              await this.prismaService.orderShipping.update({
                where: { id: orderShipping.id },
                data: {
                  status: OrderShippingStatus.FAILED,
                  lastError: orderError.message,
                  lastUpdatedAt: new Date()
                }
              })
              this.logger.log(`[SHARED_PAYMENT] OrderShipping status updated to FAILED cho order: ${order.id}`)
            }
          } catch (updateError) {
            this.logger.error(`[SHARED_PAYMENT] Lỗi khi update OrderShipping status: ${updateError.message}`)
          }

          // Continue với order tiếp theo thay vì fail toàn bộ
          continue
        }
      }

      this.logger.log(`[SHARED_PAYMENT] Hoàn thành tạo GHN orders cho tất cả orders`)
    } catch (error) {
      this.logger.error(`[SHARED_PAYMENT] Lỗi khi tạo GHN orders: ${error.message}`, error.stack)
      throw error
    }
  }

  // ... existing code ...
  // ============================================================
  async validateAndFindPayment(paymentId: number) {
    const payment = await this.prismaService.payment.findUnique({
      where: { id: paymentId },
      include: {
        orders: {
          include: {
            items: true,
            discounts: true,
            shipping: true
          }
        }
      }
    })
    if (!payment) throw new BadRequestException(`Cannot find payment with id ${paymentId}`)
    return payment
  }

  validatePaymentAmount(expectedAmount: string, actualAmount: string | number) {
    const expected = parseFloat(expectedAmount)
    const actual = parseFloat(actualAmount.toString())

    if (Math.abs(expected - actual) > 0.01) {
      throw new BadRequestException(`Price not match, expected ${expected} but got ${actual}`)
    }
  }

  async updatePaymentAndOrdersOnSuccess(paymentId: number, orders: Array<{ id: string }>) {
    this.logger.log(`[SHARED_PAYMENT] Bắt đầu xử lý thanh toán thành công cho paymentId: ${paymentId}`)
    this.logger.log(`[SHARED_PAYMENT] Orders: ${JSON.stringify(orders, null, 2)}`)

    try {
      // 1. Update payment status
      await this.updatePaymentStatus(paymentId, PaymentStatus.SUCCESS)
      this.logger.log(`[SHARED_PAYMENT] Payment status updated thành công`)

      // 2. Update orders status
      await this.updateOrdersStatus(
        orders.map((o) => o.id),
        OrderStatus.PENDING_PACKAGING
      )
      this.logger.log(`[SHARED_PAYMENT] Orders status updated thành công`)

      // 3. Tạo GHN orders cho online payment
      this.logger.log(`[SHARED_PAYMENT] Bắt đầu tạo GHN orders cho ${orders.length} orders`)
      await this.createGHNOrdersForOnlinePayment(orders)
      this.logger.log(`[SHARED_PAYMENT] Hoàn thành tạo GHN orders cho tất cả orders`)
    } catch (error) {
      this.logger.error(`[SHARED_PAYMENT] Lỗi khi xử lý thanh toán thành công: ${error.message}`)
      throw error
    }
  }

  private async updatePaymentStatus(paymentId: number, status: PaymentStatus) {
    await this.prismaService.payment.update({
      where: { id: paymentId },
      data: { status }
    })
  }

  private async updateOrdersStatus(orderIds: string[], status: OrderStatusType) {
    await this.prismaService.order.updateMany({
      where: { id: { in: orderIds } },
      data: { status }
    })
  }

  private async fetchOrderDataForShipping(orderIds: string[]) {
    this.logger.log(`[SHARED_PAYMENT] Fetch order data cho shipping cho ${orderIds.length} orders`)

    try {
      const [ordersWithDetails, orderItems, orderShippings] = await Promise.all([
        this.prismaService.order.findMany({
          where: { id: { in: orderIds } },
          include: { shop: true }
        }),
        this.prismaService.productSKUSnapshot.findMany({
          where: { orderId: { in: orderIds } }
        }),
        this.prismaService.orderShipping.findMany({
          where: { orderId: { in: orderIds } }
        })
      ])

      this.logger.log(
        `[SHARED_PAYMENT] Fetched: ${ordersWithDetails.length} orders, ${orderItems.length} items, ${orderShippings.length} shippings`
      )

      const shopIds = ordersWithDetails.map((o) => o.shopId).filter((id): id is string => Boolean(id))
      this.logger.log(`[SHARED_PAYMENT] Shop IDs: ${JSON.stringify(shopIds)}`)

      const shopAddresses = await this.prismaService.userAddress.findMany({
        where: {
          userId: { in: shopIds },
          isDefault: true
        },
        include: { address: true }
      })

      this.logger.log(`[SHARED_PAYMENT] Shop addresses: ${shopAddresses.length} addresses`)

      const result = { ordersWithDetails, orderItems, orderShippings, shopAddresses }
      this.logger.log(`[SHARED_PAYMENT] Order data fetched successfully`)
      return result
    } catch (error) {
      this.logger.error(`[SHARED_PAYMENT] Lỗi khi fetch order data: ${error.message}`, error.stack)
      throw error
    }
  }

  private async createSingleGHNOrder(order: any, orderShipping: any, orderItems: any[]) {
    this.logger.log(`[SHARED_PAYMENT] Tạo single GHN order cho order: ${order.id}`)

    try {
      const ghnOrderData = this.buildGHNOrderData(order, orderShipping, orderItems)
      this.logger.log(`[SHARED_PAYMENT] GHN order data: ${JSON.stringify(ghnOrderData, null, 2)}`)

      await this.shippingProducer.enqueueCreateOrder(ghnOrderData)
      this.logger.log(`[SHARED_PAYMENT] GHN order enqueued thành công cho order: ${order.id}`)
    } catch (error) {
      this.logger.error(`[SHARED_PAYMENT] Lỗi khi tạo GHN order: ${error.message}`, error.stack)
      throw error
    }
  }

  private buildGHNOrderData(order: any, orderShipping: any, orderItems: any[]): CreateOrderType {
    this.logger.log(`[SHARED_PAYMENT] Build GHN order data cho order: ${order.id}`)

    const orderItemsForOrder = orderItems.filter((item) => item.orderId === order.id)
    this.logger.log(`[SHARED_PAYMENT] Order items for order ${order.id}: ${orderItemsForOrder.length} items`)

    const ghnData: CreateOrderType = {
      from_address: orderShipping.fromAddress || '',
      from_name: orderShipping.fromName || '',
      from_phone: orderShipping.fromPhone || '',
      from_province_name: orderShipping.fromProvinceName || '',
      from_district_name: orderShipping.fromDistrictName || '',
      from_ward_name: orderShipping.fromWardName || '',
      to_name: orderShipping.toName || '',
      to_phone: orderShipping.toPhone || '',
      to_address: orderShipping.toAddress || '',
      to_ward_code: orderShipping.toWardCode || '',
      to_district_id: orderShipping.toDistrictId || 0,
      client_order_code: `${PAYMENT_ID_PREFIX}${order.id}`,
      cod_amount: 0, // Online payment nên cod_amount = 0
      shippingFee: orderShipping.shippingFee || 0,
      weight: orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT,
      length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
      width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
      height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT,
      service_id: orderShipping.serviceId || 0,
      service_type_id: orderShipping.serviceTypeId || 0,
      coupon: null,
      items: this.buildGHNOrderItems(orderItemsForOrder, orderShipping),
      payment_type_id: GHN_PAYMENT_TYPE.PREPAID,
      note: orderShipping.note || 'Online payment completed',
      required_note: orderShipping.requiredNote || 'CHOTHUHANG'
    }

    this.logger.log(`[SHARED_PAYMENT] GHN order data built: ${JSON.stringify(ghnData, null, 2)}`)
    return ghnData
  }

  private buildGHNOrderItems(orderItems: any[], orderShipping: any) {
    this.logger.log(`[SHARED_PAYMENT] Build GHN order items cho ${orderItems.length} items`)

    const items = orderItems.map((item) => ({
      name: `Item ${item.skuId?.substring(0, 6) || 'UNKNOWN'}`,
      quantity: item.quantity,
      weight: orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT,
      length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
      width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
      height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT
    }))

    this.logger.log(`[SHARED_PAYMENT] GHN order items built: ${JSON.stringify(items, null, 2)}`)
    return items
  }

  private async updateOrderShippingStatus(orderId: string, status: OrderShippingStatusType) {
    this.logger.log(`[SHARED_PAYMENT] Cập nhật OrderShipping status cho order: ${orderId} thành: ${status}`)

    try {
      const result = await this.prismaService.orderShipping.update({
        where: { orderId },
        data: { status }
      })

      this.logger.log(`[SHARED_PAYMENT] OrderShipping status updated successfully: ${JSON.stringify(result, null, 2)}`)
      return result
    } catch (error) {
      this.logger.error(`[SHARED_PAYMENT] Lỗi khi cập nhật OrderShipping status: ${error.message}`, error.stack)
      throw error
    }
  }

  async updatePaymentAndOrdersOnFailed(paymentId: number, orders: Array<{ id: string }>) {
    await this.updatePaymentStatus(paymentId, PaymentStatus.FAILED)
    await this.updateOrdersStatus(
      orders.map((o) => o.id),
      OrderStatus.CANCELLED
    )
    await this.paymentProducer.removeJob(paymentId)
  }

  async cancelPaymentAndOrder(paymentId: number) {
    const payment = await this.validateAndFindPayment(paymentId)
    const { orders } = payment
    const productSKUSnapshots = orders.map((order) => order.items).flat()

    await this.prismaService.$transaction(async (tx) => {
      await this.cancelPendingOrders(tx, orders)
      await this.restoreSKUStock(tx, productSKUSnapshots)
      await this.updatePaymentStatusInTransaction(tx, paymentId, PaymentStatus.FAILED)
    })

    await this.paymentProducer.removeJob(paymentId)
  }

  private async cancelPendingOrders(tx: any, orders: any[]) {
    await tx.order.updateMany({
      where: {
        id: { in: orders.map((order) => order.id) },
        status: {
          in: [OrderStatus.PENDING_PAYMENT, OrderStatus.PENDING_PACKAGING]
        },
        deletedAt: null
      },
      data: { status: OrderStatus.CANCELLED }
    })
  }

  private async restoreSKUStock(tx: any, productSKUSnapshots: any[]) {
    await Promise.all(
      productSKUSnapshots
        .filter((item) => item.skuId)
        .map((item) =>
          tx.sKU.update({
            where: { id: item.skuId as string },
            data: { stock: { increment: item.quantity } }
          })
        )
    )
  }

  private async updatePaymentStatusInTransaction(tx: any, paymentId: number, status: PaymentStatus) {
    await tx.payment.update({
      where: { id: paymentId },
      data: { status }
    })
  }

  getTotalPrice(
    orders: Array<{
      items: Array<{ skuPrice: number; quantity: number }>
      discounts?: Array<{ discountAmount: number }> | null
      shipping?: { shippingFee: number | null } | null
    }>
  ): string {
    const basePrice = this.calculateBasePrice(orders)
    const shippingFee = this.calculateTotalShippingFee(orders)
    return (basePrice + shippingFee).toString()
  }

  private calculateBasePrice(orders: any[]): number {
    return orders.reduce((totalOrder, order) => {
      const productTotal = order.items.reduce((sum: number, sku: any) => sum + sku.skuPrice * sku.quantity, 0)
      const discountTotal = (order.discounts || [])?.reduce((sum: number, d: any) => sum + d.discountAmount, 0) || 0
      return totalOrder + (productTotal - discountTotal)
    }, 0)
  }

  private calculateTotalShippingFee(orders: any[]): number {
    return orders.reduce((total, order) => total + (order.shipping?.shippingFee || 0), 0)
  }

  extractPaymentId(prefix: string, ...sources: string[]): number | null {
    for (const source of sources) {
      if (typeof source === 'string' && source.includes(prefix)) {
        const parts = source.split(prefix)
        if (parts.length > 1) {
          const id = Number(parts[1].replace(/\D/g, ''))
          if (!isNaN(id)) return id
        }
      }
    }
    return null
  }
}
