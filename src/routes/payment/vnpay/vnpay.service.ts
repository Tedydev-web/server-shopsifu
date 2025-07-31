import { Injectable } from '@nestjs/common'
import { VnpayService } from 'nestjs-vnpay'
import {
  CreateVNPayPaymentBodyType,
  CreateVNPayPaymentResType,
  VNPayBankListResType,
  VNPayReturnUrlType,
  VNPayVerifyResType,
  VNPayQueryDrBodyType,
  VNPayQueryDrResType,
  VNPayRefundBodyType,
  VNPayRefundResType
} from './vnpay.model'
import { I18nService } from 'nestjs-i18n'
import {
  VNPayInvalidChecksumException,
  VNPayDuplicateRequestException,
  VNPayRefundAlreadyProcessedException,
  VNPayTransactionNotFoundException,
  VNPayServiceUnavailableException
} from './vnpay.error'
import { VNPayRepo } from './vnpay.repo'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { WebSocketGateway, WebSocketServer } from '@nestjs/websockets'
import { Server } from 'socket.io'
import { generateRoomUserId, getDateInGMT7 } from 'src/shared/helpers'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { PREFIX_PAYMENT_CODE } from 'src/shared/constants/other.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { OrderStatus } from 'src/shared/constants/order.constant'

@Injectable()
@WebSocketGateway({ namespace: 'payment' })
export class VNPayService {
  @WebSocketServer()
  server: Server

  constructor(
    private readonly vnpayService: VnpayService,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly vnpayRepo: VNPayRepo,
    private readonly sharedWebsocketRepository: SharedWebsocketRepository,
    private readonly prismaService: PrismaService
  ) {}

  async getBankList(): Promise<VNPayBankListResType> {
    try {
      const banks = await this.vnpayService.getBankList()
      return {
        message: this.i18n.t('payment.payment.vnpay.success.GET_BANK_LIST_SUCCESS'),
        data: banks.map((bank) => ({
          bankCode: bank.bank_code,
          bankName: bank.bank_name,
          bankLogo: bank.logo_link,
          bankType: bank.bank_type,
          displayOrder: bank.display_order
        }))
      }
    } catch {
      throw VNPayServiceUnavailableException
    }
  }

  async createPayment(paymentData: CreateVNPayPaymentBodyType): Promise<CreateVNPayPaymentResType> {
    try {
      // Sử dụng payment ID thay vì order ID
      const paymentId = paymentData.orderId // orderId ở đây thực chất là payment ID

      // Thêm prefix vào orderInfo và orderId để có thể trích xuất payment ID sau này
      const orderInfoWithPrefix = `${PREFIX_PAYMENT_CODE}${paymentId}`
      const orderIdWithPrefix = `${PREFIX_PAYMENT_CODE}${paymentId}`

      const buildPaymentData: any = {
        vnp_Amount: paymentData.amount,
        vnp_OrderInfo: orderInfoWithPrefix,
        vnp_TxnRef: orderIdWithPrefix,
        vnp_IpAddr: paymentData.ipAddr,
        vnp_ReturnUrl: paymentData.returnUrl,
        vnp_Locale: paymentData.locale,
        vnp_CurrCode: paymentData.currency,
        vnp_OrderType: paymentData.orderType
      }

      // Thêm IPN URL nếu có
      if (paymentData.ipnUrl) {
        buildPaymentData.vnp_IpnUrl = paymentData.ipnUrl
      }

      // Thêm các field tùy chọn nếu có
      if (paymentData.bankCode) {
        buildPaymentData.vnp_BankCode = paymentData.bankCode
      }

      // Tạo URL thanh toán với hash
      const paymentUrl = this.vnpayService.buildPaymentUrl(buildPaymentData, {
        withHash: true,
        logger: {
          type: 'all',
          loggerFn: (data) => {
            console.log('BuildPaymentUrl log:', data.paymentUrl)
          }
        }
      })

      return {
        message: this.i18n.t('payment.payment.vnpay.success.CREATE_PAYMENT_SUCCESS'),
        data: {
          paymentUrl
        }
      }
    } catch {
      throw VNPayServiceUnavailableException
    }
  }

  async verifyReturnUrl(queryData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const verify = await this.vnpayService.verifyReturnUrl(queryData)

      // Nếu xác thực thành công và thanh toán thành công, xử lý webhook
      if (verify.isSuccess && verify.isVerified && verify.vnp_ResponseCode === '00') {
        const userId = await this.vnpayRepo.processVNPayWebhook(queryData)

        // Gửi thông báo qua WebSocket
        this.server.to(generateRoomUserId(userId)).emit('payment', {
          status: 'success',
          gateway: 'vnpay'
        })
      }

      return {
        message: this.i18n.t('payment.payment.vnpay.success.VERIFY_RETURN_SUCCESS'),
        data: {
          isSuccess: verify.isSuccess,
          isVerified: verify.isVerified,
          message: verify.message,
          vnp_Amount: Number(verify.vnp_Amount) || 0,
          vnp_TxnRef: String(verify.vnp_TxnRef || ''),
          vnp_TransactionNo: String(verify.vnp_TransactionNo || ''),
          vnp_ResponseCode: String(verify.vnp_ResponseCode || ''),
          vnp_TransactionStatus: String(verify.vnp_TransactionStatus || '')
        }
      }
    } catch (error) {
      if (error.message?.includes('checksum')) {
        throw VNPayInvalidChecksumException
      }
      throw VNPayServiceUnavailableException
    }
  }

  async verifyIpnCall(queryData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const verify = await this.vnpayService.verifyIpnCall(queryData)

      // Nếu xác thực thành công và thanh toán thành công, xử lý webhook
      if (verify.isSuccess && verify.isVerified && verify.vnp_ResponseCode === '00') {
        const userId = await this.vnpayRepo.processVNPayWebhook(queryData)

        // Gửi thông báo qua WebSocket
        this.server.to(generateRoomUserId(userId)).emit('payment', {
          status: 'success',
          gateway: 'vnpay'
        })
      }

      return {
        message: this.i18n.t('payment.payment.vnpay.success.VERIFY_IPN_SUCCESS'),
        data: {
          isSuccess: verify.isSuccess,
          isVerified: verify.isVerified,
          message: verify.message,
          vnp_Amount: Number(verify.vnp_Amount) || 0,
          vnp_TxnRef: String(verify.vnp_TxnRef || ''),
          vnp_TransactionNo: String(verify.vnp_TransactionNo || ''),
          vnp_ResponseCode: String(verify.vnp_ResponseCode || ''),
          vnp_TransactionStatus: String(verify.vnp_TransactionStatus || '')
        }
      }
    } catch (error) {
      if (error.message?.includes('checksum')) {
        throw VNPayInvalidChecksumException
      }
      throw VNPayServiceUnavailableException
    }
  }

  async queryDr(queryData: VNPayQueryDrBodyType): Promise<VNPayQueryDrResType> {
    try {
      const queryRequest = {
        vnp_RequestId: queryData.requestId,
        vnp_IpAddr: queryData.ipAddr,
        vnp_TxnRef: queryData.orderId,
        vnp_TransactionNo: queryData.transactionNo,
        vnp_OrderInfo: queryData.orderInfo,
        vnp_TransactionDate: queryData.transactionDate,
        vnp_CreateDate: queryData.createDate
      }

      const result = await this.vnpayService.queryDr(queryRequest, {
        logger: {
          type: 'all',
          loggerFn: (data) => {
            console.log('QueryDR log:', data)
          }
        }
      })

      return {
        message: this.i18n.t('payment.payment.vnpay.success.QUERY_DR_SUCCESS'),
        data: {
          isSuccess: result.isSuccess,
          isVerified: result.isVerified,
          message: result.message,
          vnp_Amount: Number(result.vnp_Amount) || 0,
          vnp_TxnRef: String(result.vnp_TxnRef || ''),
          vnp_TransactionNo: String(result.vnp_TransactionNo || ''),
          vnp_ResponseCode: String(result.vnp_ResponseCode || ''),
          vnp_TransactionStatus: String(result.vnp_TransactionStatus || '')
        }
      }
    } catch (error) {
      if (error.message?.includes('duplicate')) {
        throw VNPayDuplicateRequestException
      }
      if (error.message?.includes('not found')) {
        throw VNPayTransactionNotFoundException
      }
      throw VNPayServiceUnavailableException
    }
  }

  async refund(refundData: VNPayRefundBodyType): Promise<VNPayRefundResType> {
    try {
      const refundRequest = {
        vnp_RequestId: refundData.requestId,
        vnp_IpAddr: refundData.ipAddr,
        vnp_TxnRef: refundData.orderId,
        vnp_TransactionNo: refundData.transactionNo,
        vnp_Amount: refundData.amount,
        vnp_OrderInfo: refundData.orderInfo,
        vnp_TransactionDate: getDateInGMT7(),
        vnp_CreateDate: getDateInGMT7(),
        vnp_CreateBy: refundData.createBy,
        vnp_TransactionType: '02' // Refund transaction type
      }

      const result = await this.vnpayService.refund(refundRequest, {
        logger: {
          type: 'all',
          loggerFn: (data) => {
            console.log('Refund log:', data)
          }
        }
      })

      return {
        message: this.i18n.t('payment.payment.vnpay.success.REFUND_SUCCESS'),
        data: {
          isSuccess: result.isSuccess,
          isVerified: result.isVerified,
          message: result.message,
          vnp_Amount: Number(result.vnp_Amount) || 0,
          vnp_TxnRef: String(result.vnp_TxnRef || ''),
          vnp_TransactionNo: String(result.vnp_TransactionNo || ''),
          vnp_ResponseCode: String(result.vnp_ResponseCode || ''),
          vnp_TransactionStatus: String(result.vnp_TransactionStatus || '')
        }
      }
    } catch (error) {
      if (error.message?.includes('already processed')) {
        throw VNPayRefundAlreadyProcessedException
      }
      if (error.message?.includes('not found')) {
        throw VNPayTransactionNotFoundException
      }
      throw VNPayServiceUnavailableException
    }
  }

  /**
   * Xử lý IPN call theo đúng yêu cầu của VNPay
   * @param queryData Dữ liệu từ VNPay
   * @returns Kết quả xử lý IPN
   */
  async processIpnCall(queryData: VNPayReturnUrlType): Promise<{ RspCode: string; Message: string }> {
    try {
      // 1. Kiểm tra checksum trước tiên (Test Case 6)
      const verify = await this.vnpayService.verifyIpnCall(queryData)
      if (!verify.isVerified) {
        return { RspCode: '97', Message: 'Invalid Checksum' }
      }

      // 2. Kiểm tra order có tồn tại không (Test Case 3)
      const orderId = queryData.vnp_TxnRef
      const existingOrder = await this.prismaService.order.findFirst({
        where: { id: orderId },
        include: { user: true }
      })
      if (!existingOrder) {
        return { RspCode: '01', Message: 'Order not found' }
      }

      // 3. Kiểm tra order đã được xử lý chưa (Test Case 4)
      if (existingOrder.status === OrderStatus.DELIVERED || existingOrder.status === OrderStatus.CANCELLED) {
        return { RspCode: '02', Message: 'Order already confirmed' }
      }

      // 4. Kiểm tra amount có đúng không (Test Case 5)
      // Tính tổng tiền từ items của order
      const items = await this.prismaService.productSKUSnapshot.findMany({
        where: { orderId: orderId }
      })
      const expectedAmount = items.reduce((sum, item) => sum + item.skuPrice * item.quantity, 0) * 100
      const receivedAmount = Number(queryData.vnp_Amount)
      if (expectedAmount !== receivedAmount) {
        return { RspCode: '04', Message: 'Invalid amount' }
      }

      // 5. Xử lý theo ResponseCode (Test Case 1 & 2)
      if (queryData.vnp_ResponseCode === '00') {
        // Giao dịch thành công - cập nhật thành DELIVERED
        await this.prismaService.order.update({
          where: { id: orderId },
          data: { status: OrderStatus.DELIVERED }
        })

        // Gửi thông báo qua WebSocket
        this.server.to(generateRoomUserId(existingOrder.userId)).emit('payment', {
          status: 'success',
          gateway: 'vnpay'
        })

        return { RspCode: '00', Message: 'Confirm Success' }
      } else {
        // Giao dịch không thành công - cập nhật thành CANCELLED
        await this.prismaService.order.update({
          where: { id: orderId },
          data: { status: OrderStatus.CANCELLED }
        })

        // Gửi thông báo qua WebSocket
        this.server.to(generateRoomUserId(existingOrder.userId)).emit('payment', {
          status: 'failed',
          gateway: 'vnpay'
        })

        return { RspCode: '00', Message: 'Confirm Success' }
      }
    } catch (error) {
      console.error('VNPay IPN processing failed:', error)
      return { RspCode: '99', Message: 'Unknown error' }
    }
  }
}
