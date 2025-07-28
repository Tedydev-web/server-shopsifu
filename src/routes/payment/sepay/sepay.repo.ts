import { BadRequestException, Injectable } from '@nestjs/common'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { parse } from 'date-fns'
import { WebhookPaymentBodyType } from 'src/routes/payment/sepay/sepay.model'
import { PaymentProducer } from 'src/shared/producers/payment.producer'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PREFIX_PAYMENT_CODE } from 'src/shared/constants/other.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SharedPaymentRepository } from 'src/shared/repositories/shared-payment.repo'

@Injectable()
export class SepayRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly paymentProducer: PaymentProducer,
    private readonly sharedPaymentRepository: SharedPaymentRepository
  ) {}

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
      const totalPrice = this.sharedPaymentRepository.getTotalPrice(orders)

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
