import { Injectable, BadRequestException } from '@nestjs/common'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaymentProducer } from '../queue/producer/payment.producer'

/**
 * Repository dùng chung cho các gateway thanh toán
 */
@Injectable()
export class SharedPaymentRepository {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer
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
