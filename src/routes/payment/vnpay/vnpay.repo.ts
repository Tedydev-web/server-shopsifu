import { Injectable } from '@nestjs/common'
import { VNPay, ProductCode, VnpLocale, HashAlgorithm } from 'vnpay'
import { VNPayReturnUrlType, VNPayIpnType, CreateVNPayPaymentUrlType } from 'src/routes/payment/vnpay/vnpay.model'
import {
  VNPayPaymentNotFoundException,
  VNPayInvalidAmountException,
  VNPayOrderAlreadyConfirmedException,
  VNPayDataIntegrityException,
  VNPayPaymentFailedException,
  VNPayInvalidDataException
} from 'src/routes/payment/vnpay/vnpay.error'
import { PaymentStatus } from 'src/shared/constants/payment.constant'
import { OrderStatus } from 'src/shared/constants/order.constant'
import { PaymentGateway } from 'src/shared/constants/payment.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SharedPaymentRepository } from 'src/shared/repositories/shared-payment.repo'
import { PaymentProducer } from 'src/shared/producers/payment.producer'

@Injectable()
export class VNPayRepo {
  private vnpay: VNPay

  constructor(
    private readonly prismaService: PrismaService,
    private readonly sharedPaymentRepository: SharedPaymentRepository,
    private readonly paymentProducer: PaymentProducer
  ) {
    this.initializeVNPay()
  }

  private initializeVNPay() {
    this.vnpay = new VNPay({
      tmnCode: 'E12E8KYJ',
      secureSecret: 'VMZQECLOHDPXFBHLHMHYDLYIANSIHGQM',
      vnpayHost: 'https://sandbox.vnpayment.vn/paymentv2/vpcpay.html',
      hashAlgorithm: HashAlgorithm.SHA512
    })
  }

  createPaymentUrl(params: CreateVNPayPaymentUrlType): string {
    const formattedAmount = this.formatVNPayAmount(params.vnp_Amount)
    return this.vnpay.buildPaymentUrl({
      vnp_Amount: formattedAmount,
      vnp_IpAddr: params.vnp_IpAddr,
      vnp_TxnRef: params.vnp_TxnRef,
      vnp_OrderInfo: params.vnp_OrderInfo,
      vnp_OrderType: params.vnp_OrderType as ProductCode,
      vnp_ReturnUrl: params.vnp_ReturnUrl,
      vnp_Locale: params.vnp_Locale as VnpLocale,
      vnp_BankCode: params.vnp_BankCode
    })
  }

  verifyReturnUrl(query: any): VNPayReturnUrlType {
    try {
      const verify = this.vnpay.verifyReturnUrl(query)
      if (!verify.isVerified) {
        throw VNPayDataIntegrityException
      }
      if (!verify.isSuccess) {
        throw VNPayPaymentFailedException
      }
      return query as VNPayReturnUrlType
    } catch (error) {
      if (error instanceof Error) {
        throw error
      }
      throw VNPayInvalidDataException
    }
  }

  async handleReturnUrl(query: VNPayReturnUrlType): Promise<string> {
    // Verify the return URL data
    this.verifyReturnUrl(query)

    // Find the payment in database
    const payment = await this.prismaService.payment.findUnique({
      where: { id: query.vnp_TxnRef },
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
      throw VNPayPaymentNotFoundException
    }

    const userId = payment.orders[0].userId
    const { orders } = payment
    const totalPrice = this.sharedPaymentRepository.getTotalPrice(orders)

    // Verify amount (VNPay amount is in smallest currency unit)
    const expectedAmount = this.formatVNPayAmount(parseFloat(totalPrice))
    if (expectedAmount !== parseInt(query.vnp_Amount)) {
      throw VNPayInvalidAmountException
    }

    // Check if payment is already successful
    if (payment.status === PaymentStatus.SUCCESS) {
      throw VNPayOrderAlreadyConfirmedException
    }

    // Update payment and order status
    await this.prismaService.$transaction(async (tx) => {
      await Promise.all([
        tx.payment.update({
          where: { id: query.vnp_TxnRef },
          data: {
            status: PaymentStatus.SUCCESS,
            gateway: PaymentGateway.VNPAY
          }
        }),
        tx.order.updateMany({
          where: {
            id: { in: orders.map((order) => order.id) }
          },
          data: { status: OrderStatus.PENDING_PICKUP }
        }),
        this.paymentProducer.removeJob(query.vnp_TxnRef)
      ])
    })

    return userId
  }

  async handleIpnCall(query: VNPayIpnType): Promise<any> {
    try {
      const verify = this.vnpay.verifyIpnCall(query)

      if (!verify.isVerified) {
        return { RspCode: '97', Message: 'Checksum failed' }
      }

      if (!verify.isSuccess) {
        return { RspCode: '99', Message: 'Unknown error' }
      }

      // Find the order in database
      const payment = await this.prismaService.payment.findUnique({
        where: { id: query.vnp_TxnRef },
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
        return { RspCode: '01', Message: 'Order not found' }
      }

      // Verify amount
      const { orders } = payment
      const totalPrice = this.sharedPaymentRepository.getTotalPrice(orders)
      const expectedAmount = this.formatVNPayAmount(parseFloat(totalPrice))

      if (expectedAmount !== parseInt(query.vnp_Amount)) {
        return { RspCode: '04', Message: 'Invalid amount' }
      }

      // Check if order already confirmed
      if (payment.status === PaymentStatus.SUCCESS) {
        return { RspCode: '02', Message: 'Order already confirmed' }
      }

      // Update payment and order status
      await this.prismaService.$transaction(async (tx) => {
        await Promise.all([
          tx.payment.update({
            where: { id: query.vnp_TxnRef },
            data: {
              status: PaymentStatus.SUCCESS,
              gateway: PaymentGateway.VNPAY
            }
          }),
          tx.order.updateMany({
            where: {
              id: { in: orders.map((order) => order.id) }
            },
            data: { status: OrderStatus.PENDING_PICKUP }
          }),
          this.paymentProducer.removeJob(query.vnp_TxnRef)
        ])
      })

      return { RspCode: '00', Message: 'Confirm Success' }
    } catch (error) {
      console.error('VNPay IPN error:', error)
      return { RspCode: '99', Message: 'Unknown error' }
    }
  }

  private formatVNPayAmount(amount: number): number {
    // VNPay expects amount in VND (Vietnamese Dong)
    // Convert to smallest currency unit (VND * 100)
    return Math.round(amount * 100)
  }
}
