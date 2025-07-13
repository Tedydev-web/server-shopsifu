import { Module } from '@nestjs/common'
import { ChatGateway } from 'src/websockets/chat.gateway'

@Module({
  providers: [ChatGateway],
})
export class WebsocketModule {}
