import { Body, Controller, Get, Post, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { VNPayService } from './vnpay.service'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import {
  CreateVNPayPaymentBodyDTO,
  CreateVNPayPaymentResDTO,
  VNPayBankListResDTO,
  VNPayReturnUrlDTO,
  VNPayVerifyResDTO,
  VNPayQueryDrBodyDTO,
  VNPayQueryDrResDTO,
  VNPayRefundBodyDTO,
  VNPayRefundResDTO
} from './vnpay.dto'

@Controller('payment/vnpay')
export class VNPayController {
  constructor(private readonly vnpayService: VNPayService) {}

  /**
   * Lấy danh sách ngân hàng hỗ trợ thanh toán VNPay
   * @returns Danh sách ngân hàng
   */
  @Get('bank-list')
  @IsPublic()
  @ZodSerializerDto(VNPayBankListResDTO)
  async getBankList() {
    return this.vnpayService.getBankList()
  }

  /**
   * Tạo URL thanh toán VNPay
   * @param paymentData Dữ liệu thanh toán
   * @returns URL thanh toán và thông tin đơn hàng
   */
  @Post('create-payment')
  @IsPublic()
  @ZodSerializerDto(CreateVNPayPaymentResDTO)
  async createPayment(@Body() paymentData: CreateVNPayPaymentBodyDTO) {
    return this.vnpayService.createPayment(paymentData)
  }

  /**
   * Xác thực URL trả về từ VNPay
   * @param queryData Dữ liệu trả về từ VNPay
   * @returns Kết quả xác thực
   */
  @Get('verify-return')
  @IsPublic()
  @ZodSerializerDto(VNPayVerifyResDTO)
  async verifyReturnUrl(@Query() queryData: VNPayReturnUrlDTO) {
    return this.vnpayService.verifyReturnUrl(queryData)
  }

  /**
   * Xác thực IPN call từ VNPay
   * @param ipnData Dữ liệu IPN từ VNPay
   * @returns Kết quả xác thực IPN
   */
  @Post('verify-ipn')
  @IsPublic()
  @ZodSerializerDto(VNPayVerifyResDTO)
  async verifyIpnCall(@Body() ipnData: VNPayReturnUrlDTO) {
    return this.vnpayService.verifyIpnCall(ipnData)
  }

  /**
   * Truy vấn kết quả thanh toán từ VNPay
   * @param queryData Dữ liệu truy vấn
   * @returns Kết quả truy vấn
   */
  @Post('query-dr')
  @IsPublic()
  @ZodSerializerDto(VNPayQueryDrResDTO)
  async queryDr(@Body() queryData: VNPayQueryDrBodyDTO) {
    return this.vnpayService.queryDr(queryData)
  }

  /**
   * Hoàn tiền giao dịch VNPay
   * @param refundData Dữ liệu hoàn tiền
   * @returns Kết quả hoàn tiền
   */
  @Post('refund')
  @IsPublic()
  @ZodSerializerDto(VNPayRefundResDTO)
  async refund(@Body() refundData: VNPayRefundBodyDTO) {
    return this.vnpayService.refund(refundData)
  }
}
