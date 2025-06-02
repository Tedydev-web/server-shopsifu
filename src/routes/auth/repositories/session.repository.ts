import { Injectable, Logger, Inject } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'

export interface Session {
  id: string
  userId: number
  deviceId: number
  createdAt: Date
  expiresAt: Date
  lastActive: Date
  ipAddress: string
  userAgent: string
  isActive: boolean
  device?: {
    id: number
    name: string | null
    isTrusted: boolean
  }
}

export interface SessionPaginationOptions {
  page: number
  limit: number
}

export interface SessionPaginationResult {
  data: Session[]
  total: number
  page: number
  limit: number
  totalPages: number
}

@Injectable()
export class SessionRepository {
  private readonly logger = new Logger(SessionRepository.name)
  private readonly sessionPrefix = 'session:'

  constructor(
    private readonly prismaService: PrismaService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService
  ) {}

  /**
   * Tìm session theo ID
   */
  async findById(sessionId: string): Promise<Session | null> {
    const data = await this.redisService.hgetall(`${this.sessionPrefix}${sessionId}`)

    if (!data || Object.keys(data).length === 0) {
      return null
    }

    const session: Session = {
      id: sessionId,
      userId: parseInt(data.userId, 10),
      deviceId: parseInt(data.deviceId, 10),
      createdAt: new Date(parseInt(data.createdAt, 10)),
      expiresAt: new Date(parseInt(data.expiresAt, 10)),
      lastActive: new Date(parseInt(data.lastActive, 10)),
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      isActive: data.isActive === '1'
    }

    // Lấy thông tin device nếu có
    if (session.deviceId) {
      const device = await this.prismaService.device.findUnique({
        where: { id: session.deviceId },
        select: {
          id: true,
          name: true,
          isTrusted: true
        }
      })

      if (device) {
        session.device = device
      }
    }

    return session
  }

  /**
   * Tìm tất cả session của user
   */
  async findSessionsByUserId(userId: number, options: SessionPaginationOptions): Promise<SessionPaginationResult> {
    const { page, limit } = options
    const offset = (page - 1) * limit

    // Tìm tất cả các session key của user
    const keys = await this.redisService.keys(`${this.sessionPrefix}*`)
    const sessions: Session[] = []

    // Lấy thông tin chi tiết từng session
    for (const key of keys) {
      const sessionId = key.replace(this.sessionPrefix, '')
      const data = await this.redisService.hgetall(key)

      if (data && parseInt(data.userId, 10) === userId) {
        sessions.push({
          id: sessionId,
          userId,
          deviceId: parseInt(data.deviceId, 10),
          createdAt: new Date(parseInt(data.createdAt, 10)),
          expiresAt: new Date(parseInt(data.expiresAt, 10)),
          lastActive: new Date(parseInt(data.lastActive, 10)),
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          isActive: data.isActive === '1'
        })
      }
    }

    // Sắp xếp session theo thời gian hoạt động gần đây nhất
    sessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())

    // Phân trang
    const total = sessions.length
    const totalPages = Math.ceil(total / limit)
    const paginatedSessions = sessions.slice(offset, offset + limit)

    // Lấy thông tin device cho các session
    for (const session of paginatedSessions) {
      if (session.deviceId) {
        const device = await this.prismaService.device.findUnique({
          where: { id: session.deviceId },
          select: {
            id: true,
            name: true,
            isTrusted: true
          }
        })

        if (device) {
          session.device = device
        }
      }
    }

    return {
      data: paginatedSessions,
      total,
      page,
      limit,
      totalPages
    }
  }

  /**
   * Tạo session mới
   */
  async createSession(sessionData: {
    id: string
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    expiresAt: Date
  }): Promise<Session> {
    const { id, userId, deviceId, ipAddress, userAgent, expiresAt } = sessionData
    const now = Date.now()

    const session: Record<string, string> = {
      userId: userId.toString(),
      deviceId: deviceId.toString(),
      createdAt: now.toString(),
      expiresAt: expiresAt.getTime().toString(),
      lastActive: now.toString(),
      ipAddress,
      userAgent,
      isActive: '1'
    }

    const key = `${this.sessionPrefix}${id}`
    await this.redisService.hset(key, session)

    // TTL: thời gian hết hạn của session
    const ttlInSeconds = Math.floor((expiresAt.getTime() - now) / 1000)
    await this.redisService.expire(key, ttlInSeconds)

    return {
      id,
      userId,
      deviceId,
      createdAt: new Date(now),
      expiresAt,
      lastActive: new Date(now),
      ipAddress,
      userAgent,
      isActive: true
    }
  }

  /**
   * Cập nhật session
   */
  async updateSessionActivity(sessionId: string): Promise<void> {
    const key = `${this.sessionPrefix}${sessionId}`
    const now = Date.now()

    await this.redisService.hset(key, {
      lastActive: now.toString()
    })
  }

  /**
   * Xóa một session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = `${this.sessionPrefix}${sessionId}`
    await this.redisService.del(key)
  }

  /**
   * Xóa tất cả session của user
   */
  async deleteAllUserSessions(userId: number, excludeSessionId?: string): Promise<{ count: number }> {
    const keys = await this.redisService.keys(`${this.sessionPrefix}*`)
    let count = 0

    for (const key of keys) {
      const sessionId = key.replace(this.sessionPrefix, '')

      // Skip session cần loại trừ
      if (excludeSessionId && sessionId === excludeSessionId) {
        continue
      }

      const data = await this.redisService.hgetall(key)

      if (data && parseInt(data.userId, 10) === userId) {
        await this.redisService.del(key)
        count++
      }
    }

    return { count }
  }
}
