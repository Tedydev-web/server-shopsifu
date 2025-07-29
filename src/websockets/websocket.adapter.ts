import { INestApplicationContext } from '@nestjs/common'
import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server, Socket } from 'socket.io'
import { generateRoomUserId } from 'src/shared/helpers'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { TokenService } from 'src/shared/services/token.service'
import { createAdapter } from '@socket.io/redis-adapter'
import { createClient } from 'redis'

export class WebsocketAdapter extends IoAdapter {
  private readonly sharedWebsocketRepository: SharedWebsocketRepository
  private readonly tokenService: TokenService
  private adapterConstructor: ReturnType<typeof createAdapter>
  constructor(app: INestApplicationContext) {
    super(app)
    this.sharedWebsocketRepository = app.get(SharedWebsocketRepository)
    this.tokenService = app.get(TokenService)
  }

  async connectToRedis(): Promise<void> {
    const pubClient = createClient({ url: process.env.REDIS_URL })
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
    return server
  }

  async authMiddleware(socket: Socket, next: (err?: any) => void) {
    try {
      let accessToken: string | undefined

      console.log('🔍 WebSocket Auth Debug:')
      console.log('Headers:', socket.handshake.headers)
      console.log('Query:', socket.handshake.query)

      // 1. Thử lấy từ Authorization header
      const { authorization } = socket.handshake.headers
      if (authorization) {
        accessToken = authorization.split(' ')[1]
        console.log('✅ Found token in Authorization header')
      }

      // 2. Thử lấy từ query parameters
      if (!accessToken) {
        accessToken = socket.handshake.query.access_token as string
        if (accessToken) {
          console.log('✅ Found token in query parameters')
        }
      }

      // 3. Thử lấy từ cookie
      if (!accessToken) {
        const cookies = socket.handshake.headers.cookie
        if (cookies) {
          console.log('🍪 Cookies found:', cookies)
          const cookieArray = cookies.split(';')
          const accessTokenCookie = cookieArray.find((cookie) => cookie.trim().startsWith('access_token='))
          if (accessTokenCookie) {
            accessToken = accessTokenCookie.split('=')[1]
            console.log('✅ Found token in cookie')
          }
        }
      }

      // 4. Thử lấy từ refresh_token cookie nếu không có access_token
      if (!accessToken) {
        const cookies = socket.handshake.headers.cookie
        if (cookies) {
          const cookieArray = cookies.split(';')
          const refreshTokenCookie = cookieArray.find((cookie) => cookie.trim().startsWith('refresh_token='))
          if (refreshTokenCookie) {
            const refreshToken = refreshTokenCookie.split('=')[1]
            console.log('🔄 Found refresh token, attempting to get new access token')
            try {
              // Thử verify refresh token để lấy userId
              const { userId } = await this.tokenService.verifyRefreshToken(refreshToken)
              console.log('✅ Refresh token valid, userId:', userId)
              await socket.join(generateRoomUserId(userId))
              return next()
            } catch (error) {
              console.log('❌ Refresh token invalid:', error.message)
            }
          }
        }
      }

      if (!accessToken) {
        console.log('❌ No access token found in any source')
        return next(new Error('Thiếu access token (có thể từ Authorization header, query parameter hoặc cookie)'))
      }

      console.log('🔐 Verifying access token...')
      const { userId } = await this.tokenService.verifyAccessToken(accessToken)
      console.log('✅ Access token valid, userId:', userId)
      await socket.join(generateRoomUserId(userId))

      next()
    } catch (error) {
      console.log('❌ WebSocket auth error:', error.message)
      next(error)
    }
  }
}
