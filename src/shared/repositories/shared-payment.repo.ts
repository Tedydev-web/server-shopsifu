import { Injectable, BadRequestException } from '@nestjs/common'
import { OrderStatus, OrderStatusType } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaymentProducer } from '../queue/producer/payment.producer'
import { ShippingProducer } from '../queue/producer/shipping.producer'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus, OrderShippingStatusType } from 'src/shared/constants/order-shipping.constants'

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
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer,
    private readonly shippingProducer: ShippingProducer
  ) {}

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
    await this.updatePaymentStatus(paymentId, PaymentStatus.SUCCESS)
    await this.updateOrdersStatus(
      orders.map((o) => o.id),
      OrderStatus.PENDING_PICKUP
    )
    await this.paymentProducer.removeJob(paymentId)

    // Tạo GHN order cho online payment sau khi thanh toán thành công
    await this.createGHNOrdersForOnlinePayment(orders)
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

  private async createGHNOrdersForOnlinePayment(orders: Array<{ id: string }>) {
    try {
      const orderIds = orders.map((order) => order.id)
      const orderData = await this.fetchOrderDataForShipping(orderIds)

      for (const order of orderData.ordersWithDetails) {
        const shopAddress = orderData.shopAddresses.find((a) => a.userId === order.shopId)?.address
        const orderShipping = orderData.orderShippings.find((s) => s.orderId === order.id)

        if (shopAddress && order.receiver && orderShipping) {
          await this.createSingleGHNOrder(order, orderShipping, orderData.orderItems)
          await this.updateOrderShippingStatus(order.id, OrderShippingStatus.ENQUEUED)
        } else {
          console.error(`Missing shipping info for order ${order.id}`)
        }
      }
    } catch (error) {
      console.error('Failed to create GHN orders for online payment:', error)
      // Không throw error để không ảnh hưởng đến flow thanh toán chính
    }
  }

  private async fetchOrderDataForShipping(orderIds: string[]) {
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

    const shopIds = ordersWithDetails.map((o) => o.shopId).filter((id): id is string => Boolean(id))
    const shopAddresses = await this.prismaService.userAddress.findMany({
      where: { userId: { in: shopIds }, isDefault: true },
      include: { address: true }
    })

    return { ordersWithDetails, orderItems, orderShippings, shopAddresses }
  }

  private async createSingleGHNOrder(order: any, orderShipping: any, orderItems: any[]) {
    const ghnOrderData = this.buildGHNOrderData(order, orderShipping, orderItems)
    await this.shippingProducer.enqueueCreateOrder(ghnOrderData)
  }

  private buildGHNOrderData(order: any, orderShipping: any, orderItems: any[]) {
    const orderItemsForOrder = orderItems.filter((item) => item.orderId === order.id)

    return {
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
      content: undefined,
      weight: orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT,
      length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
      width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
      height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT,
      pick_station_id: undefined,
      insurance_value: undefined,
      service_id: orderShipping.serviceId || undefined,
      service_type_id: orderShipping.serviceTypeId || undefined,
      config_fee_id: orderShipping.configFeeId || undefined,
      extra_cost_id: orderShipping.extraCostId || undefined,
      coupon: null,
      pick_shift: orderShipping.pickShift ? JSON.parse(orderShipping.pickShift as string) : undefined,
      items: this.buildGHNOrderItems(orderItemsForOrder, orderShipping),
      payment_type_id: GHN_PAYMENT_TYPE.PREPAID,
      note: orderShipping.note || 'Online payment completed',
      required_note: orderShipping.requiredNote || 'CHOTHUHANG'
    }
  }

  private buildGHNOrderItems(orderItems: any[], orderShipping: any) {
    return orderItems.map((item) => ({
      name: `Item ${item.skuId?.substring(0, 6) || 'UNKNOWN'}`,
      quantity: item.quantity,
      weight: orderShipping.weight || SHIPPING_DEFAULTS.WEIGHT,
      length: orderShipping.length || SHIPPING_DEFAULTS.LENGTH,
      width: orderShipping.width || SHIPPING_DEFAULTS.WIDTH,
      height: orderShipping.height || SHIPPING_DEFAULTS.HEIGHT
    }))
  }

  private async updateOrderShippingStatus(orderId: string, status: OrderShippingStatusType) {
    await this.prismaService.orderShipping.update({
      where: { orderId },
      data: { status }
    })
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
        status: OrderStatus.PENDING_PAYMENT,
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
