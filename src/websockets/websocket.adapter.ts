import { INestApplicationContext, UnauthorizedException } from '@nestjs/common'
import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server, Socket } from 'socket.io'
import { generateRoomUserId } from 'src/shared/helpers'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { TokenService } from 'src/shared/services/token.service'
import { createAdapter } from '@socket.io/redis-adapter'
import { createClient } from 'redis'
import { ConfigService } from '@nestjs/config'

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
        origin: this.configService.getOrThrow('app.cors.origin'),
        credentials: this.configService.getOrThrow('app.cors.credentials')
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
    return server
  }

  async authMiddleware(socket: Socket, next: (err?: any) => void) {
    try {
      let accessToken: string | undefined

      // 1. Thử lấy từ Authorization header
      const { authorization } = socket.handshake.headers
      if (authorization) {
        accessToken = authorization.split(' ')[1]
      }

      // 2. Thử lấy từ query parameters
      if (!accessToken) {
        accessToken = socket.handshake.query.access_token as string
      }

      // 3. Thử lấy từ cookie
      if (!accessToken) {
        const cookies = socket.handshake.headers.cookie
        if (cookies) {
          const cookieArray = cookies.split(';')
          const accessTokenCookie = cookieArray.find((cookie) => cookie.trim().startsWith('access_token='))
          if (accessTokenCookie) accessToken = accessTokenCookie.split('=')[1]
        }
      }

      if (!accessToken) return next(new UnauthorizedException('Thiếu access token'))

      const { userId } = await this.tokenService.verifyAccessToken(accessToken)
      await socket.join(generateRoomUserId(userId))

      next()
    } catch (error) {
      next(error)
    }
  }
}
