// vnpay.controller.ts
import { Controller, Get, Query, Req, Res } from '@nestjs/common'
import { VnpayService } from './vnpay.service'
import { Request, Response } from 'express'

@Controller('vnpay')
export class VnpayController {
  constructor(private vnpayService: VnpayService) {}

  @Get('create-paymentUrl')
  createPayment(@Query('orderId') orderId: string, @Query('amount') amount: number, @Req() req: Request) {
    const ip = req.ip || '127.0.0.1'
    const url = this.vnpayService.createPaymentUrl(orderId, Number(amount), ip)
    return { url }
  }

  @Get('vnpay-return')
  async vnpayReturn(@Query() query: any, @Res() res: Response) {
    const isValid = this.vnpayService.validateCallback(query)

    if (isValid) {
      const orderId = query.vnp_TxnRef
      // cập nhật đơn hàng thành paid ở đây
      console.log(`✅ Payment for order ${orderId} is valid.`)

      return res.redirect(`http://localhost:3000/success`)
    } else {
      console.log(`❌ Invalid callback`)
      return res.redirect(`http://localhost:3000/fail`)
    }
  }
}
