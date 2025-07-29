import { Injectable } from '@nestjs/common'
import { VnpayService } from 'nestjs-vnpay'
import { BuildPaymentUrl } from 'vnpay'
import {
  CreateVNPayPaymentBodyType,
  CreateVNPayPaymentResType,
  VNPayBankListResType,
  VNPayReturnUrlType,
  VNPayVerifyResType
} from './vnpay.model'

@Injectable()
export class VNPayService {
  constructor(private readonly vnpayService: VnpayService) {}

  /**
   * Lấy danh sách ngân hàng hỗ trợ thanh toán VNPay
   * @returns Danh sách ngân hàng
   */
  async getBankList(): Promise<VNPayBankListResType> {
    try {
      const banks = await this.vnpayService.getBankList()
      return {
        banks: banks.map((bank) => ({
          bankCode: bank.bank_code,
          bankName: bank.bank_name,
          bankLogo: bank.logo_link
        }))
      }
    } catch (error) {
      throw new Error('Không thể lấy danh sách ngân hàng: ' + error.message)
    }
  }

  /**
   * Tạo URL thanh toán VNPay
   * @param paymentData Dữ liệu thanh toán
   * @returns URL thanh toán và thông tin đơn hàng
   */
  async createPayment(paymentData: CreateVNPayPaymentBodyType): Promise<CreateVNPayPaymentResType> {
    try {
      // Chuyển đổi dữ liệu từ DTO sang BuildPaymentUrl
      const buildPaymentData: BuildPaymentUrl = {
        vnp_Amount: paymentData.amount,
        vnp_OrderInfo: paymentData.orderInfo,
        vnp_TxnRef: paymentData.orderId,
        vnp_ReturnUrl: paymentData.returnUrl,
        vnp_Locale: paymentData.locale,
        vnp_CurrCode: paymentData.currency,
        vnp_BankCode: paymentData.bankCode,
        vnp_IpAddr: '127.0.0.1' // IP mặc định, có thể lấy từ request
      }

      // Tạo URL thanh toán
      const paymentUrl = this.vnpayService.buildPaymentUrl(buildPaymentData)

      return {
        paymentUrl,
        orderId: paymentData.orderId,
        amount: paymentData.amount,
        orderInfo: paymentData.orderInfo
      }
    } catch (error) {
      throw new Error('Không thể tạo URL thanh toán: ' + error.message)
    }
  }

  /**
   * Xác thực URL trả về từ VNPay
   * @param queryData Dữ liệu trả về từ VNPay
   * @returns Kết quả xác thực
   */
  async verifyReturnUrl(queryData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const result = await this.vnpayService.verifyReturnUrl(queryData)

      return {
        isSuccess: result.isSuccess,
        isVerified: result.isVerified,
        message: result.message,
        data: {
          orderId: result.vnp_TxnRef,
          amount: result.vnp_Amount,
          transactionNo: result.vnp_TransactionNo,
          responseCode: result.vnp_ResponseCode,
          transactionStatus: result.vnp_TransactionStatus,
          bankCode: result.vnp_BankCode,
          bankTranNo: result.vnp_BankTranNo,
          payDate: result.vnp_PayDate
        }
      }
    } catch (error) {
      return {
        isSuccess: false,
        isVerified: false,
        message: 'Không thể xác thực URL trả về: ' + error.message
      }
    }
  }

  /**
   * Xác thực IPN call từ VNPay
   * @param ipnData Dữ liệu IPN từ VNPay
   * @returns Kết quả xác thực IPN
   */
  async verifyIpnCall(ipnData: VNPayReturnUrlType): Promise<VNPayVerifyResType> {
    try {
      const result = await this.vnpayService.verifyIpnCall(ipnData)

      return {
        isSuccess: result.isSuccess,
        isVerified: result.isVerified,
        message: result.message,
        data: {
          orderId: result.vnp_TxnRef,
          amount: result.vnp_Amount,
          transactionNo: result.vnp_TransactionNo,
          responseCode: result.vnp_ResponseCode,
          transactionStatus: result.vnp_TransactionStatus,
          bankCode: result.vnp_BankCode,
          bankTranNo: result.vnp_BankTranNo,
          payDate: result.vnp_PayDate
        }
      }
    } catch (error) {
      return {
        isSuccess: false,
        isVerified: false,
        message: 'Không thể xác thực IPN call: ' + error.message
      }
    }
  }
}
