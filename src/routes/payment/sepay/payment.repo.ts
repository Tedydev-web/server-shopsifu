import { BadRequestException, Injectable } from '@nestjs/common'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { parse } from 'date-fns'
import { WebhookPaymentBodyType } from 'src/routes/payment/sepay/payment.model'
import { PaymentProducer } from 'src/routes/payment/sepay/payment.producer'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PREFIX_PAYMENT_CODE } from 'src/shared/constants/other.constant'
import { OrderIncludeProductSKUSnapshotAndDiscountType } from 'src/shared/models/shared-order.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class PaymentRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer
  ) {}

  private getTotalPrice(orders: OrderIncludeProductSKUSnapshotAndDiscountType[]): string {
    return orders
      .reduce((total, order) => {
        // Tính tổng tiền sản phẩm
        const productTotal = order.items.reduce((totalPrice: number, productSku: any) => {
          return totalPrice + productSku.skuPrice * productSku.quantity
        }, 0)

        // Tính tổng giảm giá từ DiscountSnapshot
        const discountTotal =
          order.discounts?.reduce((totalDiscount: number, discount: any) => {
            return totalDiscount + discount.discountAmount
          }, 0) || 0

        // Cộng vào tổng (đã trừ giảm giá)
        return total + (productTotal - discountTotal)
      }, 0)
      .toString()
  }

  async receiver(body: WebhookPaymentBodyType): Promise<string> {
    // 1. Thêm thông tin giao dịch vào DB
    // Tham khảo: https://docs.sepay.vn/lap-trinh-webhooks.html
    let amountIn = 0
    let amountOut = 0
    if (body.transferType === 'in') {
      amountIn = body.transferAmount
    } else if (body.transferType === 'out') {
      amountOut = body.transferAmount
    }

    const paymentTransaction = await this.prismaService.paymentTransaction.findUnique({
      where: { id: body.id }
    })

    if (paymentTransaction) {
      throw new BadRequestException('Transaction already exists')
    }

    const userId = await this.prismaService.$transaction(async (tx) => {
      await tx.paymentTransaction.create({
        data: {
          id: body.id,
          gateway: body.gateway,
          transactionDate: parse(body.transactionDate, 'yyyy-MM-dd HH:mm:ss', new Date()),
          accountNumber: body.accountNumber,
          subAccount: body.subAccount,
          amountIn,
          amountOut,
          accumulated: body.accumulated,
          code: body.code,
          transactionContent: body.content,
          referenceNumber: body.referenceCode,
          body: body.description
        }
      })

      // 2. Kiểm tra nội dung chuyển khoản và tổng số tiền có khớp hay không
      const paymentId = body.code
        ? body.code.split(PREFIX_PAYMENT_CODE)[1]
        : body.content?.split(PREFIX_PAYMENT_CODE)[1]

      if (!paymentId) {
        throw new BadRequestException('Cannot get payment id from content')
      }

      const payment = await tx.payment.findUnique({
        where: { id: paymentId },
        include: {
          orders: {
            include: {
              items: true,
              discounts: true
            }
          }
        }
      })

      if (!payment) {
        throw new BadRequestException(`Cannot find payment with id ${paymentId}`)
      }

      const userId = payment.orders[0].userId
      const { orders } = payment
      const totalPrice = this.getTotalPrice(orders)

      if (totalPrice !== body.transferAmount.toString()) {
        throw new BadRequestException(`Price not match, expected ${totalPrice} but got ${body.transferAmount}`)
      }

      // 3. Cập nhật trạng thái đơn hàng
      await Promise.all([
        tx.payment.update({
          where: { id: paymentId },
          data: { status: PaymentStatus.SUCCESS }
        }),
        tx.order.updateMany({
          where: {
            id: { in: orders.map((order) => order.id) }
          },
          data: { status: OrderStatus.PENDING_PICKUP }
        }),
        this.paymentProducer.removeJob(paymentId)
      ])

      return userId
    })

    return userId
  }
}
