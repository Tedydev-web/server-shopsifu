import { Injectable, BadRequestException } from '@nestjs/common'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaymentProducer } from '../queue/producer/payment.producer'
import { ShippingProducer } from '../queue/producer/shipping.producer'
import { ConfigService } from '@nestjs/config'
import { GHN_PAYMENT_TYPE } from 'src/shared/constants/shipping.constants'
import { OrderShippingStatus } from 'src/shared/constants/order-shipping.constants'

/**
 * Repository dùng chung cho các gateway thanh toán
 */
@Injectable()
export class SharedPaymentRepository {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer,
    private readonly shippingProducer: ShippingProducer,
    private readonly configService: ConfigService
  ) {}

  /**
   * Tìm payment kèm orders, nếu không có thì throw
   */
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

  /**
   * Kiểm tra số tiền thanh toán có khớp không
   * @param orders - Danh sách orders
   * @param expectedAmount - Số tiền mong đợi (VND)
   * @param actualAmount - Số tiền thực tế (VND)
   */
  validatePaymentAmount(expectedAmount: string, actualAmount: string | number) {
    const expected = parseFloat(expectedAmount)
    const actual = parseFloat(actualAmount.toString())

    // So sánh với tolerance 0.01 để tránh lỗi float precision
    if (Math.abs(expected - actual) > 0.01) {
      throw new BadRequestException(`Price not match, expected ${expected} but got ${actual}`)
    }
  }

  /**
   * Cập nhật trạng thái payment và orders khi thanh toán thành công
   */
  async updatePaymentAndOrdersOnSuccess(paymentId: number, orders: Array<{ id: string }>) {
    await Promise.all([
      this.prismaService.payment.update({
        where: { id: paymentId },
        data: { status: PaymentStatus.SUCCESS }
      }),
      this.prismaService.order.updateMany({
        where: { id: { in: orders.map((order) => order.id) } },
        data: { status: OrderStatus.PENDING_PICKUP }
      }),
      this.paymentProducer.removeJob(paymentId)
    ])

    // Tạo GHN order cho online payment sau khi thanh toán thành công
    await this.createGHNOrdersForOnlinePayment(orders)
  }

  /**
   * Tạo GHN orders cho online payment sau khi thanh toán thành công
   */
  private async createGHNOrdersForOnlinePayment(orders: Array<{ id: string }>) {
    try {
      // Lấy thông tin đầy đủ của orders với shipping info
      const orderIds = orders.map((order) => order.id)

      const [ordersWithDetails, orderItems, shopAddresses] = await Promise.all([
        // Lấy thông tin cơ bản của orders
        this.prismaService.order.findMany({
          where: { id: { in: orderIds } },
          include: {
            shop: true
          }
        }),

        // Lấy items của orders
        this.prismaService.productSKUSnapshot.findMany({
          where: { orderId: { in: orderIds } }
        }),

        // Lấy địa chỉ shop
        this.prismaService.userAddress.findMany({
          where: {
            userId: {
              in: (
                await this.prismaService.order.findMany({ where: { id: { in: orderIds } }, select: { shopId: true } })
              )
                .map((o) => o.shopId)
                .filter((id): id is string => Boolean(id))
            },
            isDefault: true
          },
          include: { address: true }
        })
      ])

      // Lấy thông tin shipping riêng
      const orderShippings = await this.prismaService.orderShipping.findMany({
        where: { orderId: { in: orderIds } }
      })

      // Tạo GHN order cho mỗi order có shipping info
      for (const order of ordersWithDetails) {
        // Tìm địa chỉ shop tương ứng
        const shopAddress = shopAddresses.find((a) => a.userId === order.shopId)?.address
        // Tìm OrderShipping tương ứng với order
        const orderShipping = orderShippings.find((s) => s.orderId === order.id)

        if (shopAddress && order.receiver && orderShipping) {
          const receiver = order.receiver as any

          // Sử dụng thông tin từ OrderShipping đã lưu trước đó
          await this.shippingProducer.enqueueCreateOrder({
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
            cod_amount: 0, // Online payment nên cod_amount = 0
            shippingFee: orderShipping.shippingFee || 0,
            content: undefined,
            weight: orderShipping.weight || 1000,
            length: orderShipping.length || 30,
            width: orderShipping.width || 20,
            height: orderShipping.height || 15,
            pick_station_id: undefined,
            insurance_value: undefined,
            service_id: orderShipping.serviceId || undefined,
            service_type_id: orderShipping.serviceTypeId || undefined,
            config_fee_id: orderShipping.configFeeId || undefined,
            extra_cost_id: orderShipping.extraCostId || undefined,
            coupon: null,
            pick_shift: orderShipping.pickShift ? JSON.parse(orderShipping.pickShift as string) : undefined,
            items: orderItems
              .filter((item) => item.orderId === order.id)
              .map((item) => ({
                name: `Item ${item.skuId?.substring(0, 6) || 'UNKNOWN'}`,
                quantity: item.quantity,
                weight: orderShipping.weight || 1000,
                length: orderShipping.length || 30,
                width: orderShipping.width || 20,
                height: orderShipping.height || 15
              })),
            payment_type_id: GHN_PAYMENT_TYPE.PREPAID,
            note: orderShipping.note || 'Online payment completed',
            required_note: orderShipping.requiredNote || 'CHOTHUHANG'
          })

          // Cập nhật trạng thái OrderShipping thành ENQUEUED
          await this.prismaService.orderShipping.update({
            where: { orderId: order.id },
            data: { status: OrderShippingStatus.ENQUEUED }
          })
        } else {
          console.error(`Missing shipping info for order ${order.id}`)
        }
      }
    } catch (error) {
      console.error('Failed to create GHN orders for online payment:', error)
      // Không throw error để không ảnh hưởng đến flow thanh toán chính
    }
  }

  /**
   * Cập nhật trạng thái payment và orders khi thanh toán thất bại
   */
  async updatePaymentAndOrdersOnFailed(paymentId: number, orders: Array<{ id: string }>) {
    await Promise.all([
      this.prismaService.payment.update({
        where: { id: paymentId },
        data: { status: PaymentStatus.FAILED }
      }),
      this.prismaService.order.updateMany({
        where: { id: { in: orders.map((order) => order.id) } },
        data: { status: OrderStatus.CANCELLED }
      }),
      this.paymentProducer.removeJob(paymentId)
    ])
  }

  /**
   * Hủy payment và orders, hoàn lại stock cho SKU (dùng cho queue, nghiệp vụ hủy tự động)
   */
  async cancelPaymentAndOrder(paymentId: number) {
    const payment = await this.prismaService.payment.findUnique({
      where: { id: paymentId },
      include: {
        orders: {
          include: { items: true }
        }
      }
    })
    if (!payment) throw new BadRequestException('Payment not found')
    const { orders } = payment
    const productSKUSnapshots = orders.map((order) => order.items).flat()

    await this.prismaService.$transaction(async (tx) => {
      // Chỉ hủy các order đang PENDING_PAYMENT và chưa bị xóa
      await tx.order.updateMany({
        where: {
          id: { in: orders.map((order) => order.id) },
          status: OrderStatus.PENDING_PAYMENT,
          deletedAt: null
        },
        data: { status: OrderStatus.CANCELLED }
      })
      // Hoàn lại stock cho SKU
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
      // Update trạng thái payment thành FAILED
      await tx.payment.update({
        where: { id: paymentId },
        data: { status: PaymentStatus.FAILED }
      })
    })
    // Xóa job khỏi queue nếu có
    await this.paymentProducer.removeJob(paymentId)
  }

  /**
   * Tính tổng tiền các order bao gồm shipping fee (đã trừ giảm giá)
   */
  getTotalPrice(
    orders: Array<{
      items: Array<{ skuPrice: number; quantity: number }>
      discounts?: Array<{ discountAmount: number }> | null
      shipping?: { shippingFee: number | null } | null
    }>
  ): string {
    const basePrice = orders.reduce((totalOrder, order) => {
      const productTotal = order.items.reduce((sum: number, sku: any) => sum + sku.skuPrice * sku.quantity, 0)
      const discountTotal = (order.discounts || [])?.reduce((sum: number, d: any) => sum + d.discountAmount, 0) || 0
      return totalOrder + (productTotal - discountTotal)
    }, 0)

    const shippingFee = orders.reduce((total, order) => total + (order.shipping?.shippingFee || 0), 0)
    return (basePrice + shippingFee).toString()
  }

  /**
   * Trích xuất paymentId từ nhiều nguồn (code, content, vnp_TxnRef, ...)
   */
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
