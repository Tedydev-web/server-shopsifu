import { Controller, Post, Get, Body, Query } from '@nestjs/common'
import { VNPayService } from './vnpay.service'
import { CreateVNPayPaymentUrlDTO, CreateVNPayPaymentUrlResDTO, VNPayReturnUrlDTO, VNPayIpnDTO } from './vnpay.dto'
import { ZodSerializerDto } from 'nestjs-zod'
import { MessageResDTO } from 'src/shared/dtos/response.dto'

@Controller('payment/vnpay')
export class VNPayController {
  constructor(private readonly vnpayService: VNPayService) {}

  @Post('create-url')
  @ZodSerializerDto(CreateVNPayPaymentUrlResDTO)
  createPaymentUrl(@Body() body: CreateVNPayPaymentUrlDTO) {
    return this.vnpayService.createPaymentUrl(body)
  }

  @Get('return')
  @ZodSerializerDto(MessageResDTO)
  handleReturnUrl(@Query() query: VNPayReturnUrlDTO) {
    return this.vnpayService.handleReturnUrl(query)
  }

  @Post('ipn')
  @ZodSerializerDto(MessageResDTO)
  handleIpnCall(@Body() body: VNPayIpnDTO) {
    return this.vnpayService.handleIpnCall(body)
  }

  @Get('test')
  @ZodSerializerDto(MessageResDTO)
  test() {
    return { message: 'VNPayController is working!' }
  }
}
