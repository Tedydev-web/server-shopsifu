import { BadRequestException, Injectable } from '@nestjs/common'
import { parse } from 'date-fns'
import { WebhookPaymentBodyType } from 'src/routes/payment/sepay/sepay.model'
import { PaymentProducer } from 'src/shared/queue/producer/payment.producer'
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

  async receiver(body: WebhookPaymentBodyType): Promise<{ userId: string; paymentId: number }> {
    // 1. Lưu transaction vào DB
    let amountIn = 0
    let amountOut = 0
    if (body.transferType === 'in') amountIn = body.transferAmount
    else if (body.transferType === 'out') amountOut = body.transferAmount

    const paymentTransaction = await this.prismaService.paymentTransaction.findUnique({
      where: { id: body.id }
    })
    if (paymentTransaction) throw new BadRequestException('Transaction already exists')

    const result = await this.prismaService.$transaction(async (tx) => {
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

      // 2. Dùng extractPaymentId của shared repo
      const paymentId = this.sharedPaymentRepository.extractPaymentId(
        PREFIX_PAYMENT_CODE,
        ...(body.code ? [body.code] : []),
        ...(body.content ? [body.content] : [])
      )
      if (!paymentId) throw new BadRequestException('Cannot get payment id from content')

      // 3. Validate và tìm payment với orders
      const payment = await this.sharedPaymentRepository.validateAndFindPayment(Number(paymentId))
      const userId = payment.orders[0].userId
      const { orders } = payment

      // 4. Validate số tiền
      this.sharedPaymentRepository.validatePaymentAmount(
        this.sharedPaymentRepository.getTotalPrice(orders),
        body.transferAmount
      )

      // 5. Cập nhật trạng thái payment và orders
      await this.sharedPaymentRepository.updatePaymentAndOrdersOnSuccess(Number(paymentId), orders)

      return { userId, paymentId: Number(paymentId) }
    })

    return result
  }
}
