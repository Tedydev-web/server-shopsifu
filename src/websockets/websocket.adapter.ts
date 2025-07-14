import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server } from 'socket.io'

export class WebsocketAdapter extends IoAdapter {
  createIOServer(port: number, options?: ServerOptions) {
    const server: Server = super.createIOServer(port, {
      ...options,
      cors: {
        origin: '*',
        credentials: true,
      },
    })
    return server
  }
}
