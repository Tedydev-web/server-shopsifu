import { Injectable, Logger, Inject, Optional } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { CRYPTO_SERVICE, REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { CryptoService } from 'src/shared/services/crypto.service'
import { isObject } from 'src/shared/utils/type-guards.utils'
import { safeNumber } from 'src/shared/utils/validation.utils'

export interface Session {
  id: string
  userId: number
  deviceId: number
  createdAt: number // Use timestamp for easier serialization
  expiresAt: number // Use timestamp
  lastActive: number // Use timestamp
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

// Định nghĩa interface cho Redis operation
interface RedisOperation {
  command: string
  args: any[]
}

// Định nghĩa interface cho phiên được lưu trong Redis
interface SessionInRedis {
  key: string
  data: Record<string, string>
}

@Injectable()
export class SessionRepository {
  private readonly logger = new Logger(SessionRepository.name)
  // Các trường nhạy cảm cần được mã hóa trong Redis
  private readonly sensitiveFields = ['ipAddress', 'userAgent']

  constructor(
    private readonly prismaService: PrismaService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(CRYPTO_SERVICE) @Optional() private readonly cryptoService?: CryptoService
  ) {}

  /**
   * Finds a session by its ID from Redis.
   * @returns The decrypted session object or null if not found.
   */
  async findById(sessionId: string): Promise<Session | null> {
    const key = RedisKeyManager.getSessionKey(sessionId)
    this.logger.debug(`[findById] Looking for session with key: ${key}`)

    const sessionData = await this.redisService.hgetallDecrypted<Session>(key, this.sensitiveFields)

    if (!sessionData || !isObject(sessionData)) {
      this.logger.debug(`[findById] No session found for key ${key}`)
      return null
    }

    // Ensure correct types after retrieval from Redis (which stores everything as strings)
    return this.normalizeSessionTypes(sessionData)
  }

  /**
   * Finds all sessions for a given user with pagination.
   */
  async findSessionsByUserId(userId: number, options: SessionPaginationOptions): Promise<SessionPaginationResult> {
    const { page = 1, limit = 10 } = options
    const userSessionIdsKey = RedisKeyManager.getUserSessionsKey(userId)
    const sessionIds = await this.redisService.smembers(userSessionIdsKey)

    if (!sessionIds || sessionIds.length === 0) {
      return { data: [], total: 0, page, limit, totalPages: 0 }
    }

    const pipeline = this.redisService.client.pipeline()
    sessionIds.forEach((id) => pipeline.hgetall(RedisKeyManager.getSessionKey(id)))
    const results = await pipeline.exec()

    const allSessions: Session[] = []
    if (results) {
      for (let i = 0; i < results.length; i++) {
        const [error, sessionData] = results[i]
        const sessionId = sessionIds[i]

        if (error || !sessionData || Object.keys(sessionData).length === 0) {
          continue
        }
        const decryptedData = await this.redisService.hgetallDecrypted<Session>(
          RedisKeyManager.getSessionKey(sessionId),
          this.sensitiveFields,
          sessionData as Record<string, string>
        )
        if (decryptedData && isObject(decryptedData) && decryptedData.userId?.toString() === userId.toString()) {
          allSessions.push(this.normalizeSessionTypes(decryptedData))
        }
      }
    }

    allSessions.sort((a, b) => b.lastActive - a.lastActive) // Sort by most recent

    const totalItems = allSessions.length
    const startIndex = (page - 1) * limit
    const paginatedSessions = allSessions.slice(startIndex, startIndex + limit)

    return {
      data: paginatedSessions,
      total: totalItems,
      page,
      limit,
      totalPages: Math.ceil(totalItems / limit)
    }
  }

  /**
   * Creates a new session in Redis.
   * The session data is stored as an encrypted hash.
   */
  async createSession(sessionData: Omit<Session, 'lastActive' | 'isActive'>): Promise<Session> {
    const now = Date.now()
    const newSession: Session = {
      ...sessionData,
      lastActive: now,
      isActive: true
    }

    const key = RedisKeyManager.getSessionKey(newSession.id)
    const ttlSeconds = Math.floor((newSession.expiresAt - now) / 1000)

    await this.redisService.hsetEncrypted(key, newSession as any, this.sensitiveFields)
    if (ttlSeconds > 0) {
      await this.redisService.expire(key, ttlSeconds)
    }

    // Add session to user and device indexes
    const pipeline = this.redisService.client.pipeline()
    pipeline.sadd(RedisKeyManager.getUserSessionsKey(newSession.userId), newSession.id)
    pipeline.sadd(RedisKeyManager.getDeviceSessionsKey(newSession.deviceId), newSession.id)
    await pipeline.exec()

    this.logger.debug(
      `Session created: ${newSession.id} for user ${newSession.userId}, expires in ${ttlSeconds} seconds`
    )

    return newSession
  }

  /**
   * Updates the last active timestamp for a session.
   */
  async updateSessionActivity(sessionId: string): Promise<void> {
    const key = RedisKeyManager.getSessionKey(sessionId)
    await this.redisService.hset(key, 'lastActive', Date.now().toString())
    this.logger.debug(`Updated activity for session ${sessionId}`)
  }

  /**
   * Deletes a session from Redis and its indexes.
   */
  async deleteSession(sessionId: string): Promise<void> {
    const session = await this.findById(sessionId)
    if (!session) {
      this.logger.warn(`[deleteSession] Session ${sessionId} not found for deletion.`)
      return
    }

    const pipeline = this.redisService.client.pipeline()
    pipeline.del(RedisKeyManager.getSessionKey(sessionId))
    pipeline.srem(RedisKeyManager.getUserSessionsKey(session.userId), sessionId)
    pipeline.srem(RedisKeyManager.getDeviceSessionsKey(session.deviceId), sessionId)
    await pipeline.exec()

    this.logger.debug(`Session ${sessionId} deleted and removed from indexes.`)
  }

  /**
   * Deletes all sessions for a user, with an option to exclude one.
   * Also returns a list of trusted device IDs that became session-less.
   */
  async deleteAllUserSessions(
    userId: number,
    excludeSessionId?: string
  ): Promise<{ count: number; untrustedDeviceIds: number[] }> {
    const userSessionIdsKey = RedisKeyManager.getUserSessionsKey(userId)
    let sessionIds = await this.redisService.smembers(userSessionIdsKey)

    if (!sessionIds || sessionIds.length === 0) {
      return { count: 0, untrustedDeviceIds: [] }
    }

    if (excludeSessionId) {
      sessionIds = sessionIds.filter((id) => id !== excludeSessionId)
    }

    if (sessionIds.length === 0) {
      return { count: 0, untrustedDeviceIds: [] }
    }

    const sessions = (await Promise.all(sessionIds.map((id) => this.findById(id)))).filter(
      (s): s is Session => s !== null
    )

    const deviceIdsWithDeletedSessions = new Set<number>()
    sessions.forEach((s) => deviceIdsWithDeletedSessions.add(s.deviceId))

    const pipeline = this.redisService.client.pipeline()
    sessions.forEach((s) => {
      pipeline.del(RedisKeyManager.getSessionKey(s.id))
      pipeline.srem(RedisKeyManager.getDeviceSessionsKey(s.deviceId), s.id)
    })

    // Remove the revoked sessions from the user's session index
    if (excludeSessionId) {
      pipeline.srem(userSessionIdsKey, ...sessionIds)
    } else {
      pipeline.del(userSessionIdsKey)
    }
    await pipeline.exec()

    // Find which of the affected devices are now session-less and were trusted
    const untrustedDeviceIds: number[] = []
    for (const deviceId of Array.from(deviceIdsWithDeletedSessions)) {
      const remainingCount = await this.countSessionsByDeviceId(deviceId)
      if (remainingCount === 0) {
        // This logic can be simplified if we fetch device trust status here
        // For now, we return the ID and let the service handle untrusting
        untrustedDeviceIds.push(deviceId)
      }
    }

    this.logger.debug(`Deleted ${sessions.length} sessions for user ${userId}.`)
    return { count: sessions.length, untrustedDeviceIds }
  }

  /**
   * Deletes all sessions associated with a specific device.
   * @param deviceId The ID of the device.
   * @param excludeSessionId An optional session ID to exclude from deletion.
   * @returns The number of sessions deleted.
   */
  async deleteSessionsByDeviceId(deviceId: number, excludeSessionId?: string): Promise<{ count: number }> {
    const deviceSessionsKey = RedisKeyManager.getDeviceSessionsKey(deviceId)
    let sessionIds = await this.redisService.smembers(deviceSessionsKey)

    if (excludeSessionId) {
      sessionIds = sessionIds.filter((id) => id !== excludeSessionId)
    }

    if (sessionIds.length === 0) {
      return { count: 0 }
    }

    const sessions = (await Promise.all(sessionIds.map((id) => this.findById(id)))).filter(
      (s): s is Session => s !== null
    )

    const pipeline = this.redisService.client.pipeline()
    sessions.forEach((s) => {
      pipeline.del(RedisKeyManager.getSessionKey(s.id))
      pipeline.srem(RedisKeyManager.getUserSessionsKey(s.userId), s.id)
    })
    pipeline.del(deviceSessionsKey) // Delete the whole set for the device
    await pipeline.exec()

    return { count: sessionIds.length }
  }

  /**
   * Counts the number of active sessions for a specific device.
   * @param deviceId The ID of the device.
   * @returns The number of sessions.
   */
  async countSessionsByDeviceId(deviceId: number): Promise<number> {
    const deviceSessionsKey = RedisKeyManager.getDeviceSessionsKey(deviceId)
    return this.redisService.scard(deviceSessionsKey)
  }

  /**
   * Marks a session as inactive in Redis.
   */
  async deactivateSession(sessionId: string): Promise<void> {
    const key = RedisKeyManager.getSessionKey(sessionId)
    await this.redisService.hset(key, 'isActive', 'false')
    this.logger.debug(`Session ${sessionId} has been deactivated.`)
  }

  /**
   * Converts fields of a session object from string to their correct types.
   */
  private normalizeSessionTypes(sessionData: Record<string, any>): Session {
    return {
      id: sessionData.id,
      userId: safeNumber(sessionData.userId, 0),
      deviceId: safeNumber(sessionData.deviceId, 0),
      createdAt: safeNumber(sessionData.createdAt, 0),
      expiresAt: safeNumber(sessionData.expiresAt, 0),
      lastActive: safeNumber(sessionData.lastActive, 0),
      ipAddress: sessionData.ipAddress,
      userAgent: sessionData.userAgent,
      isActive: sessionData.isActive === 'true' || sessionData.isActive === true
    }
  }
}
