import { MessageBody, SubscribeMessage, WebSocketGateway, WebSocketServer } from '@nestjs/websockets'
import { Server } from 'socket.io'

@WebSocketGateway({ namespace: 'payment' })
export class PaymentGateway {
  @WebSocketServer()
  server: Server

  // afterInit(server: Server) {
  //   console.log('WebSocket server initialized')
  // }

  // handleConnection(client: Socket, ...args: any[]) {
  //   console.log(`Client connected: ${client.id}`)
  // }

  // handleDisconnect(client: Socket) {
  //   console.log(`Client disconnected: ${client.id}`)
  // }

  @SubscribeMessage('send-money')
  handleEvent(@MessageBody() data: string): string {
    this.server.emit('receive-money', {
      data: `Money: ${data}`
    })
    return data
  }
}
