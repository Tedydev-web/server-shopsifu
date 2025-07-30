import { INestApplicationContext } from '@nestjs/common'
import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server, Socket } from 'socket.io'
import { generateRoomUserId } from 'src/shared/helpers'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { TokenService } from 'src/shared/services/token.service'
import { createAdapter } from '@socket.io/redis-adapter'
import { createClient } from 'redis'
import { ConfigService } from '@nestjs/config'
import { parse } from 'cookie'

const namespaces = ['/', 'payment', 'chat']
export class WebsocketAdapter extends IoAdapter {
  private readonly sharedWebsocketRepository: SharedWebsocketRepository
  private readonly tokenService: TokenService
  private adapterConstructor: ReturnType<typeof createAdapter>
  private readonly configService: ConfigService
  constructor(app: INestApplicationContext) {
    super(app)
    this.sharedWebsocketRepository = app.get(SharedWebsocketRepository)
    this.tokenService = app.get(TokenService)
    this.configService = app.get(ConfigService)
  }

  async connectToRedis(): Promise<void> {
    const pubClient = createClient({ url: this.configService.getOrThrow('redis.url') })
    const subClient = pubClient.duplicate()

    await Promise.all([pubClient.connect(), subClient.connect()])

    this.adapterConstructor = createAdapter(pubClient, subClient)
  }

  createIOServer(port: number, options?: ServerOptions) {
    const server: Server = super.createIOServer(port, {
      ...options,
      cors: {
        origin: '*',
        credentials: true
      }
    })

    server.use((socket, next) => {
      this.authMiddleware(socket, next)
        .then(() => {})
        .catch(() => {})
    })
    server.of(/.*/).use((socket, next) => {
      this.authMiddleware(socket, next)
        .then(() => {})
        .catch(() => {})
    })
    // namespaces.forEach((item) => {
    //   server.of(item).use(authMiddleware)
    // })
    // server.use(authMiddleware)
    // server.of('payment').use(authMiddleware)
    // server.of('chat').use(authMiddleware)
    return server
  }

  async authMiddleware(socket: Socket, next: (err?: any) => void) {
    const { authorization, cookie } = socket.handshake.headers
    let accessToken: string | undefined
    if (authorization) {
      accessToken = authorization.split(' ')[1]
    }
    if (!accessToken && cookie) {
      const cookies = parse(cookie)
      accessToken = cookies['access_token']
    }
    if (!accessToken) {
      return next(new Error('Thiếu access token'))
    }
    try {
      const { userId } = await this.tokenService.verifyAccessToken(accessToken)
      await socket.join(generateRoomUserId(userId))
      next()
    } catch (error) {
      next(error)
    }
  }
}
