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
    this.logger.debug(
      `[findSessionsByUserId] Finding sessions for userId: ${userId} with options: ${JSON.stringify(options)}`
    )
    // Lấy tất cả các key session chung
    const allSessionKeysPattern = `${this.sessionPrefix}*`
    this.logger.debug(`[findSessionsByUserId] Fetching all session keys with pattern: ${allSessionKeysPattern}`)

    let allPossibleSessionKeys: string[] = []
    try {
      allPossibleSessionKeys = await this.redisService.keys(allSessionKeysPattern)
      this.logger.debug(
        `[findSessionsByUserId] Found ${allPossibleSessionKeys.length} possible keys: ${JSON.stringify(
          allPossibleSessionKeys
        )}`
      )
    } catch (error) {
      this.logger.error(`[findSessionsByUserId] Error fetching keys from Redis: ${error.message}`, error.stack)
      return {
        data: [],
        total: 0,
        page: options.page,
        limit: options.limit,
        totalPages: 0
      }
    }

    const userSessionKeys: string[] = []
    for (const key of allPossibleSessionKeys) {
      try {
        const storedUserId = await this.redisService.hget(key, 'userId')
        if (storedUserId && parseInt(storedUserId, 10) === userId) {
          userSessionKeys.push(key)
        }
      } catch (error) {
        this.logger.error(`[findSessionsByUserId] Error checking userId for key ${key}: ${error.message}`, error.stack)
      }
    }

    this.logger.debug(
      `[findSessionsByUserId] Found ${userSessionKeys.length} keys matching userId ${userId}: ${JSON.stringify(
        userSessionKeys
      )}`
    )

    if (userSessionKeys.length === 0) {
      this.logger.debug(`[findSessionsByUserId] No session keys found for userId: ${userId}`)
      return {
        data: [],
        total: 0,
        page: options.page,
        limit: options.limit,
        totalPages: 0
      }
    }

    const sessions: Session[] = []
    for (const key of userSessionKeys) {
      try {
        const sessionData = await this.redisService.hgetall(key)
        this.logger.debug(`[findSessionsByUserId] Raw data for key ${key}: ${JSON.stringify(sessionData)}`)
        if (sessionData && Object.keys(sessionData).length > 0) {
          const sessionIdFromKey = key.split(':')[1]
          const session = this.mapRedisDataToSession(sessionData, sessionIdFromKey)
          if (session) {
            sessions.push(session)
          }
        } else {
          this.logger.warn(`[findSessionsByUserId] No data or empty data found for key ${key}`)
        }
      } catch (error) {
        this.logger.error(`[findSessionsByUserId] Error processing key ${key}: ${error.message}`, error.stack)
      }
    }

    // Sắp xếp session theo lastActive giảm dần (mới nhất trước)
    sessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())
    this.logger.debug(
      `[findSessionsByUserId] Found ${sessions.length} sessions before pagination for userId: ${userId}`
    )

    const total = sessions.length
    const { page, limit } = options
    const offset = (page - 1) * limit
    const totalPages = Math.ceil(total / limit)
    const paginatedSessions = sessions.slice(offset, offset + limit)

    // Lấy thông tin device cho các session đã phân trang
    for (const session of paginatedSessions) {
      if (session.deviceId) {
        try {
          const device = await this.prismaService.device.findUnique({
            where: { id: session.deviceId },
            select: { id: true, name: true, isTrusted: true }
          })
          session.device = device || undefined // Gán undefined nếu không tìm thấy device
        } catch (error) {
          this.logger.error(
            `[findSessionsByUserId] Error fetching device info for deviceId: ${session.deviceId}, error: ${error.message}`,
            error.stack
          )
          session.device = undefined // Gán undefined nếu có lỗi
        }
      }
    }

    this.logger.debug(
      `[findSessionsByUserId] Returning ${paginatedSessions.length} sessions for userId: ${userId} after pagination.`
    )

    return {
      data: paginatedSessions,
      total,
      page,
      limit,
      totalPages
    }
  }

  private mapRedisDataToSession(redisData: Record<string, string>, sessionId: string): Session | null {
    if (
      !redisData.userId ||
      !redisData.deviceId ||
      !redisData.createdAt ||
      !redisData.lastActive ||
      !redisData.expiresAt // Đảm bảo expiresAt tồn tại và là một số hợp lệ
    ) {
      this.logger.warn(
        `[mapRedisDataToSession] Missing required fields for session ID: ${sessionId}. Data: ${JSON.stringify(
          redisData
        )}`
      )
      return null
    }
    try {
      const userId = parseInt(redisData.userId, 10)
      const deviceId = parseInt(redisData.deviceId, 10)
      const createdAt = parseInt(redisData.createdAt, 10)
      const expiresAt = parseInt(redisData.expiresAt, 10)
      const lastActive = parseInt(redisData.lastActive, 10)

      if (isNaN(userId) || isNaN(deviceId) || isNaN(createdAt) || isNaN(expiresAt) || isNaN(lastActive)) {
        this.logger.warn(
          `[mapRedisDataToSession] Invalid numeric fields for session ID: ${sessionId}. Data: ${JSON.stringify(
            redisData
          )}`
        )
        return null
      }

      return {
        id: sessionId,
        userId: userId,
        deviceId: deviceId,
        createdAt: new Date(createdAt),
        expiresAt: new Date(expiresAt),
        lastActive: new Date(lastActive),
        ipAddress: redisData.ipAddress || 'N/A',
        userAgent: redisData.userAgent || 'N/A',
        isActive: redisData.isActive === '1'
        // device sẽ được lấy sau khi phân trang
      }
    } catch (error) {
      this.logger.error(
        `[mapRedisDataToSession] Error mapping data for session ID: ${sessionId}. Data: ${JSON.stringify(redisData)}, Error: ${error.message}`
      )
      return null
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
    this.logger.debug(`[createSession] Starting for sessionId: ${id}, userId: ${userId}, deviceId: ${deviceId}`)
    this.logger.debug(
      `[createSession] Input expiresAt: ${expiresAt.toISOString()}, ipAddress: ${ipAddress}, userAgent: ${userAgent}`
    )

    const now = Date.now()
    const createdAtTimestamp = now
    const expiresAtTimestamp = expiresAt.getTime()
    const lastActiveTimestamp = now

    this.logger.debug(
      `[createSession] Timestamps: createdAt=${new Date(createdAtTimestamp).toISOString()}, expiresAt=${new Date(expiresAtTimestamp).toISOString()}, lastActive=${new Date(lastActiveTimestamp).toISOString()}`
    )

    if (expiresAtTimestamp <= createdAtTimestamp) {
      this.logger.error(
        `[createSession] Invalid expiresAt time for session ${id}. expiresAt (${new Date(expiresAtTimestamp).toISOString()}) must be after createdAt (${new Date(createdAtTimestamp).toISOString()}).`
      )
      throw new Error('Session expiration time is invalid.')
    }

    const sessionRedisData: Record<string, string> = {
      userId: userId.toString(),
      deviceId: deviceId.toString(),
      createdAt: createdAtTimestamp.toString(),
      expiresAt: expiresAtTimestamp.toString(),
      lastActive: lastActiveTimestamp.toString(),
      ipAddress,
      userAgent,
      isActive: '1'
    }

    const key = `${this.sessionPrefix}${id}`
    this.logger.debug(`[createSession] Redis key: ${key}, Session data to store: ${JSON.stringify(sessionRedisData)}`)

    try {
      const hsetResult = await this.redisService.hset(key, sessionRedisData)
      this.logger.debug(`[createSession] Redis hset result for key ${key}: ${hsetResult}`)
    } catch (error) {
      this.logger.error(`[createSession] Error during redisService.hset for key ${key}: ${error.message}`, error.stack)
      throw error // Re-throw error để service gọi có thể xử lý
    }

    const ttlInSeconds = Math.floor((expiresAtTimestamp - createdAtTimestamp) / 1000)
    this.logger.debug(`[createSession] Calculated TTL for key ${key}: ${ttlInSeconds}s`)

    if (ttlInSeconds <= 0) {
      this.logger.warn(
        `[createSession] Calculated TTL for session ${id} is ${ttlInSeconds}s, which is invalid. Setting a default TTL of 1 day (86400s).`
      )
      try {
        const expireResult = await this.redisService.expire(key, 86400) // Mặc định 1 ngày nếu TTL không hợp lệ
        this.logger.debug(`[createSession] Redis expire (default TTL) result for key ${key}: ${expireResult}`)
      } catch (error) {
        this.logger.error(
          `[createSession] Error during redisService.expire (default TTL) for key ${key}: ${error.message}`,
          error.stack
        )
        throw error // Re-throw error
      }
    } else {
      try {
        const expireResult = await this.redisService.expire(key, ttlInSeconds)
        this.logger.debug(`[createSession] Redis expire result for key ${key}: ${expireResult}`)
      } catch (error) {
        this.logger.error(
          `[createSession] Error during redisService.expire for key ${key}: ${error.message}`,
          error.stack
        )
        throw error // Re-throw error
      }
    }

    const createdSessionObject: Session = {
      id,
      userId,
      deviceId,
      createdAt: new Date(createdAtTimestamp),
      expiresAt: new Date(expiresAtTimestamp),
      lastActive: new Date(lastActiveTimestamp),
      ipAddress,
      userAgent,
      isActive: true
    }
    this.logger.debug(
      `[createSession] Session created successfully and returning object: ${JSON.stringify(createdSessionObject)}`
    )
    return createdSessionObject
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
    const allKeysPattern = `${this.sessionPrefix}*`
    this.logger.debug(`[deleteAllUserSessions] Fetching all session keys with pattern: ${allKeysPattern}`)
    const keys = await this.redisService.keys(allKeysPattern)
    let count = 0

    this.logger.debug(
      `[deleteAllUserSessions] Found ${keys.length} total session keys. Filtering for userId: ${userId}.`
    )

    for (const key of keys) {
      try {
        const sessionIdFromKey = key.replace(this.sessionPrefix, '')

        // Skip session cần loại trừ
        if (excludeSessionId && sessionIdFromKey === excludeSessionId) {
          this.logger.debug(`[deleteAllUserSessions] Skipping excluded session: ${sessionIdFromKey}`)
          continue
        }

        const sessionUserId = await this.redisService.hget(key, 'userId')

        if (sessionUserId && parseInt(sessionUserId, 10) === userId) {
          this.logger.debug(
            `[deleteAllUserSessions] Deleting session: ${key} for userId: ${userId} (sessionId: ${sessionIdFromKey})`
          )
          await this.redisService.del(key)
          count++
        } else if (sessionUserId) {
          this.logger.debug(`[deleteAllUserSessions] Skipping session: ${key} (belongs to userId: ${sessionUserId})`)
        } else {
          this.logger.warn(`[deleteAllUserSessions] Session key ${key} does not have a userId field. Skipping.`)
        }
      } catch (error) {
        this.logger.error(
          `[deleteAllUserSessions] Error processing key ${key} for deletion: ${error.message}`,
          error.stack
        )
      }
    }

    this.logger.debug(`[deleteAllUserSessions] Deleted ${count} sessions for userId: ${userId}`)
    return { count }
  }
}
