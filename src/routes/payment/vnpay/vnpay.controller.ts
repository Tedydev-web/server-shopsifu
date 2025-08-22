import { Body, Controller, Get, Post, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { VNPayService } from './vnpay.service'
import { IsPublic, SkipTransform } from 'src/shared/decorators/auth.decorator'
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

  @Get('bank-list')
  @IsPublic()
  @ZodSerializerDto(VNPayBankListResDTO)
  async getBankList() {
    return this.vnpayService.getBankList()
  }

  @Post('create-payment')
  @IsPublic()
  @ZodSerializerDto(CreateVNPayPaymentResDTO)
  async createPayment(@Body() paymentData: CreateVNPayPaymentBodyDTO) {
    return this.vnpayService.createPayment(paymentData as any)
  }

  @Get('verify-return')
  @IsPublic()
  @ZodSerializerDto(VNPayVerifyResDTO)
  async verifyReturnUrl(@Query() queryData: VNPayReturnUrlDTO) {
    return this.vnpayService.verifyReturnUrl(queryData as any)
  }

  @Get('verify-ipn')
  @IsPublic()
  @SkipTransform()
  async verifyIpnCall(@Query() queryData: VNPayReturnUrlDTO): Promise<{ RspCode: string; Message: string }> {
    return await this.vnpayService.processIpnCall(queryData as any)
  }

  @Post('query-dr')
  @IsPublic()
  @ZodSerializerDto(VNPayQueryDrResDTO)
  async queryDr(@Body() queryData: VNPayQueryDrBodyDTO) {
    return this.vnpayService.queryDr(queryData as any)
  }

  @Post('refund')
  @IsPublic()
  @ZodSerializerDto(VNPayRefundResDTO)
  async refund(@Body() refundData: VNPayRefundBodyDTO) {
    return this.vnpayService.refund(refundData as any)
  }
}
