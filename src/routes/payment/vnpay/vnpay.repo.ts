import { BadRequestException, Injectable } from '@nestjs/common'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { VNPayReturnUrlType } from './vnpay.model'
import { PREFIX_PAYMENT_CODE } from 'src/shared/constants/other.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SharedPaymentRepository } from 'src/shared/repositories/shared-payment.repo'

@Injectable()
export class VNPayRepo {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly sharedPaymentRepository: SharedPaymentRepository
  ) {}

  /**
   * Xử lý webhook từ VNPay khi thanh toán thành công
   * @param vnpayData Dữ liệu từ VNPay webhook
   * @returns userId của user đã thanh toán
   */
  async processVNPayWebhook(vnpayData: VNPayReturnUrlType): Promise<string> {
    // Kiểm tra xem transaction đã được xử lý chưa
    const existingTransaction = await this.prismaService.paymentTransaction.findFirst({
      where: {
        gateway: 'vnpay',
        referenceNumber: vnpayData.vnp_TransactionNo
      }
    })

    if (existingTransaction) {
      throw new BadRequestException('Transaction already processed')
    }

    const userId = await this.prismaService.$transaction(async (tx) => {
      // 1. Lưu thông tin giao dịch VNPay
      await tx.paymentTransaction.create({
        data: {
          gateway: 'vnpay',
          transactionDate: new Date(),
          accountNumber: vnpayData.vnp_BankCode,
          subAccount: vnpayData.vnp_BankTranNo,
          amountIn: Number(vnpayData.vnp_Amount),
          amountOut: 0,
          accumulated: 0,
          code: vnpayData.vnp_TxnRef,
          transactionContent: vnpayData.vnp_OrderInfo,
          referenceNumber: vnpayData.vnp_TransactionNo,
          body: JSON.stringify(vnpayData)
        }
      })

      // 2. Tìm payment ID từ order ID hoặc nội dung giao dịch
      const paymentId = this.extractPaymentId(vnpayData.vnp_OrderInfo, vnpayData.vnp_TxnRef)

      if (!paymentId) {
        throw new BadRequestException('Cannot extract payment ID from VNPay data')
      }

      // 3. Validate và tìm payment với orders
      const payment = await this.sharedPaymentRepository.validateAndFindPayment(paymentId)

      const userId = payment.orders[0].userId
      const { orders } = payment

      // 4. Validate số tiền
      this.sharedPaymentRepository.validatePaymentAmount(
        orders,
        this.sharedPaymentRepository.getTotalPrice(orders),
        vnpayData.vnp_Amount
      )

      // 5. Cập nhật trạng thái payment và orders
      await this.sharedPaymentRepository.updatePaymentAndOrdersOnSuccess(paymentId, orders)

      return userId
    })

    return userId
  }

  /**
   * Tạo payment record cho VNPay
   * @param orderIds Danh sách order IDs
   * @returns Payment ID
   */
  async createVNPayPayment(orderIds: string[]): Promise<string> {
    const payment = await this.prismaService.payment.create({
      data: {
        status: PaymentStatus.PENDING
      }
    })

    // Cập nhật orders với payment ID
    await this.prismaService.order.updateMany({
      where: {
        id: { in: orderIds }
      },
      data: {
        paymentId: payment.id
      }
    })

    return payment.id
  }

  /**
   * Trích xuất payment ID từ nội dung giao dịch hoặc order ID
   * @param orderInfo Nội dung giao dịch
   * @param orderId Order ID
   * @returns Payment ID hoặc null
   */
  private extractPaymentId(orderInfo: string, orderId: string): string | null {
    // Thử tìm payment ID từ orderInfo
    if (orderInfo.includes(PREFIX_PAYMENT_CODE)) {
      const parts = orderInfo.split(PREFIX_PAYMENT_CODE)
      if (parts.length > 1) {
        return parts[1].trim()
      }
    }

    // Thử tìm payment ID từ orderId
    if (orderId.includes(PREFIX_PAYMENT_CODE)) {
      const parts = orderId.split(PREFIX_PAYMENT_CODE)
      if (parts.length > 1) {
        return parts[1].trim()
      }
    }

    return null
  }
}
