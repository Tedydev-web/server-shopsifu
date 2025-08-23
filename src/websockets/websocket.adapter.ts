import { INestApplicationContext } from '@nestjs/common'
import { IoAdapter } from '@nestjs/platform-socket.io'
import { ServerOptions, Server, Socket } from 'socket.io'
import { generateRoomUserId, generateRoomPaymentId, generateRoomUserDevice } from 'src/shared/helpers'
import { SharedWebsocketRepository } from 'src/shared/repositories/shared-websocket.repo'
import { TokenService } from 'src/shared/services/token.service'
import { RedisService } from 'src/shared/services/redis.service'
import { createAdapter } from '@socket.io/redis-adapter'
import { ConfigService } from '@nestjs/config'
import { parse } from 'cookie'

const namespaces = ['/', 'payment', 'chat']
export class WebsocketAdapter extends IoAdapter {
  private readonly sharedWebsocketRepository: SharedWebsocketRepository
  private readonly tokenService: TokenService
  private readonly redisService: RedisService
  private adapterConstructor: ReturnType<typeof createAdapter>
  private readonly configService: ConfigService
  private pubClient: any
  private subClient: any

  constructor(app: INestApplicationContext) {
    super(app)
    this.sharedWebsocketRepository = app.get(SharedWebsocketRepository)
    this.tokenService = app.get(TokenService)
    this.redisService = app.get(RedisService)
    this.configService = app.get(ConfigService)
  }

  async connectToRedis(): Promise<void> {
    try {
      if (!this.redisService) {
        console.error('❌ RedisService is not available')
        console.log('⚠️ Continuing without Redis adapter for WebSocket')
        return
      }

      // Sử dụng Redis client từ RedisService
      const redisClient = this.redisService.getClient()

      if (!redisClient) {
        console.error('❌ Redis client is not available from RedisService')
        console.log('⚠️ Continuing without Redis adapter for WebSocket')
        return
      }

      // Tạo adapter sử dụng Redis client từ RedisService
      this.adapterConstructor = createAdapter(redisClient, redisClient.duplicate())

      console.log('✅ Redis adapter connected successfully using RedisService')
    } catch (error) {
      console.error('❌ Failed to connect Redis adapter:', error)
      console.log('⚠️ Continuing without Redis adapter for WebSocket')
      // Không throw error để không làm crash server
    }
  }

  async close(): Promise<void> {
    try {
      if (this.pubClient) {
        await this.pubClient.quit()
      }
      if (this.subClient) {
        await this.subClient.quit()
      }
      console.log('✅ Redis adapter disconnected successfully')
    } catch (error) {
      console.error('❌ Failed to disconnect Redis adapter:', error)
    }
  }

  createIOServer(port: number, options?: ServerOptions) {
    const server: Server = super.createIOServer(port, {
      ...options,
      cors: {
        origin: '*',
        credentials: true
      }
    })

    // Áp dụng Redis adapter cho server
    if (this.adapterConstructor) {
      server.adapter(this.adapterConstructor)
      console.log('✅ Redis adapter applied to WebSocket server')
    } else {
      console.log('⚠️ WebSocket server running without Redis adapter (multi-process events may not work)')
    }

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

    // Áp dụng auth middleware cho từng namespace cụ thể
    namespaces.forEach((namespace) => {
      server.of(namespace).use((socket, next) => {
        this.authMiddleware(socket, next)
          .then(() => {})
          .catch(() => {})
      })
    })

    // Thêm event handlers cho connection và disconnection
    server.on('connection', (socket) => {
      console.log(`🔌 WebSocket client connected: ${socket.id}`)

      socket.on('disconnect', (reason) => {
        console.log(`🔌 WebSocket client disconnected: ${socket.id}, reason: ${reason}`)
      })
    })

    // Thêm event handlers cho từng namespace
    namespaces.forEach((namespace) => {
      server.of(namespace).on('connection', (socket) => {
        console.log(`🔌 WebSocket client connected to namespace ${namespace}: ${socket.id}`)

        socket.on('disconnect', (reason) => {
          console.log(`🔌 WebSocket client disconnected from namespace ${namespace}: ${socket.id}, reason: ${reason}`)
        })

        socket.on('error', (error) => {
          console.error(`❌ WebSocket error in namespace ${namespace}:`, error)
        })
      })
    })

    // Thêm error handler cho server
    server.on('error', (error) => {
      console.error('❌ WebSocket server error:', error)
    })

    return server
  }

  async authMiddleware(socket: Socket, next: (err?: any) => void) {
    try {
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

      const { userId, deviceId } = await this.tokenService.verifyAccessToken(accessToken)

      // Join room dựa trên userId và deviceId (cho các event khác ngoài payment)
      await socket.join(generateRoomUserDevice(userId, deviceId))

      // Vẫn giữ user room để backward compatibility
      await socket.join(generateRoomUserId(userId))

      // Kiểm tra xem có paymentId trong query parameters không
      const { paymentId } = socket.handshake.query
      if (paymentId && typeof paymentId === 'string') {
        const roomName = generateRoomPaymentId(parseInt(paymentId))
        await socket.join(roomName)
        console.log(`✅ User ${userId} (Device: ${deviceId}) joined payment room: ${roomName}`)
      }

      console.log(`✅ User ${userId} (Device: ${deviceId}) authenticated for WebSocket connection`)
      next()
    } catch (error) {
      console.error('❌ WebSocket authentication failed:', error)
      next(error)
    }
  }
}
