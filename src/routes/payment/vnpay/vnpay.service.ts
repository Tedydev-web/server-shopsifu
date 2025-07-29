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

@Injectable()
export class VNPayService {
  constructor(
    private readonly vnpayService: VnpayService,
    private readonly i18n: I18nService
  ) {}

  /**
   * Lấy danh sách ngân hàng hỗ trợ thanh toán VNPay
   * @returns Danh sách ngân hàng
   */
  async getBankList(): Promise<VNPayBankListResType> {
    try {
      const banks = await this.vnpayService.getBankList()
      return {
        message: this.i18n.t('payment.vnpay.success.GET_BANK_LIST_SUCCESS'),
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

  /**
   * Tạo URL thanh toán VNPay
   * @param paymentData Dữ liệu thanh toán
   * @returns URL thanh toán và thông tin đơn hàng
   */
  async createPayment(paymentData: CreateVNPayPaymentBodyType): Promise<CreateVNPayPaymentResType> {
    try {
      const buildPaymentData: any = {
        vnp_Amount: paymentData.amount,
        vnp_OrderInfo: paymentData.orderInfo,
        vnp_TxnRef: paymentData.orderId,
        vnp_IpAddr: paymentData.ipAddr,
        vnp_ReturnUrl: paymentData.returnUrl,
        vnp_Locale: paymentData.locale,
        vnp_CurrCode: paymentData.currency,
        vnp_OrderType: paymentData.orderType
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
        data: {
          paymentUrl,
          orderId: paymentData.orderId,
          amount: paymentData.amount,
          orderInfo: paymentData.orderInfo
        }
      }
    } catch {
      throw VNPayServiceUnavailableException
    }
  }

  /**
   * Xác thực URL trả về từ VNPay
   * @param queryData Dữ liệu trả về từ VNPay
   * @returns Kết quả xác thực
   */
  async verifyReturnUrl(queryData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const verify = await this.vnpayService.verifyReturnUrl(queryData)

      return {
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

  /**
   * Xác thực IPN call từ VNPay
   * @param ipnData Dữ liệu IPN từ VNPay
   * @returns Kết quả xác thực IPN
   */
  async verifyIpnCall(ipnData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const verify = await this.vnpayService.verifyIpnCall(ipnData)

      return {
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

  /**
   * Truy vấn kết quả thanh toán từ VNPay
   * @param queryData Dữ liệu truy vấn
   * @returns Kết quả truy vấn
   */
  async queryDr(queryData: VNPayQueryDrBodyType): Promise<VNPayQueryDrResType> {
    try {
      const formattedDate = this.getDateInGMT7()

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

  /**
   * Hoàn tiền giao dịch VNPay
   * @param refundData Dữ liệu hoàn tiền
   * @returns Kết quả hoàn tiền
   */
  async refund(refundData: VNPayRefundBodyType): Promise<VNPayRefundResType> {
    try {
      const formattedDate = this.getDateInGMT7()

      const refundRequest = {
        vnp_RequestId: refundData.requestId,
        vnp_IpAddr: refundData.ipAddr,
        vnp_TxnRef: refundData.orderId,
        vnp_TransactionNo: refundData.transactionNo,
        vnp_Amount: refundData.amount,
        vnp_OrderInfo: refundData.orderInfo,
        vnp_TransactionDate: formattedDate,
        vnp_CreateDate: formattedDate,
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
   * Lấy ngày hiện tại theo múi giờ GMT+7
   * @returns Ngày theo định dạng yyyyMMddHHmmss
   */
  private getDateInGMT7(): number {
    const now = new Date()
    const gmt7Offset = 7 * 60 // GMT+7 in minutes
    const gmt7Time = new Date(now.getTime() + gmt7Offset * 60 * 1000)

    const year = gmt7Time.getUTCFullYear()
    const month = String(gmt7Time.getUTCMonth() + 1).padStart(2, '0')
    const day = String(gmt7Time.getUTCDate()).padStart(2, '0')
    const hours = String(gmt7Time.getUTCHours()).padStart(2, '0')
    const minutes = String(gmt7Time.getUTCMinutes()).padStart(2, '0')
    const seconds = String(gmt7Time.getUTCSeconds()).padStart(2, '0')

    return parseInt(`${year}${month}${day}${hours}${minutes}${seconds}`)
  }
}
