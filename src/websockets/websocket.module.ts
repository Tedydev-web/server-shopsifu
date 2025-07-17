import { Module } from '@nestjs/common'
import { ChatGateway } from 'src/websockets/chat.gateway'
import { PaymentGateway } from 'src/websockets/payment.gateway'

@Module({
  providers: [ChatGateway, PaymentGateway],
})
export class WebsocketModule {}
