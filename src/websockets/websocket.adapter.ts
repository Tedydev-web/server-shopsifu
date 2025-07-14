import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server, Socket } from 'socket.io'

const namespaces = ['/', 'payment', 'chat']
export class WebsocketAdapter extends IoAdapter {
  createIOServer(port: number, options?: ServerOptions) {
    const server: Server = super.createIOServer(port, {
      ...options,
      cors: {
        origin: '*',
        credentials: true,
      },
    })
    const authMiddleware = (socket: Socket, next: (err?: any) => void) => {
      console.log('connected', socket.id)
      socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`)
      })
      next()
    }
    server.use(authMiddleware)
    server.of(/.*/).use(authMiddleware)
    // namespaces.forEach((item) => {
    //   server.of(item).use(authMiddleware)
    // })
    // server.use(authMiddleware)
    // server.of('payment').use(authMiddleware)
    // server.of('chat').use(authMiddleware)
    return server
  }
}
