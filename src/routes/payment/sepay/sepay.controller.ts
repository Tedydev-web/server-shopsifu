import { Controller, Post, Body } from '@nestjs/common'
import { SepayService } from './sepay.service'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { ZodSerializerDto } from 'nestjs-zod'
import { Auth } from 'src/shared/decorators/auth.decorator'
import { WebhookPaymentBodyDTO } from 'src/routes/payment/sepay/sepay.dto'

@Controller('payment')
export class SepayController {
  constructor(private readonly sepayService: SepayService) {}

  @Post('/receiver')
  @ZodSerializerDto(MessageResDTO)
  @Auth(['PaymentAPIKey'])
  receiver(@Body() body: WebhookPaymentBodyDTO) {
    return this.sepayService.receiver(body as any)
  }
}
