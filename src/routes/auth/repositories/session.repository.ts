import { Injectable, Logger, Inject } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { LOGIN_HISTORY_TTL } from '../constants/auth.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { CryptoService } from 'src/shared/services/crypto.service'

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

  constructor(
    private readonly prismaService: PrismaService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly cryptoService?: CryptoService
  ) {}

  /**
   * Tìm session theo ID
   */
  async findById(sessionId: string): Promise<Session | null> {
    const key = RedisKeyManager.sessionKey(sessionId)
    this.logger.debug(`[findById] Looking for session with ID ${sessionId}, Redis key: ${key}`)

    let sessionData: Record<string, string>

    // Nếu có cryptoService, kiểm tra xem có dữ liệu đã mã hóa không
    if (this.cryptoService) {
      try {
        const encryptedData = await this.redisService.hgetall(key)
        if (!encryptedData || Object.keys(encryptedData).length === 0) {
          this.logger.debug(`[findById] No session found for ID ${sessionId}`)
          return null
        }

        // Giải mã các trường nhạy cảm
        const sensitiveFields = ['ipAddress', 'userAgent']
        sessionData = { ...encryptedData }

        for (const field of sensitiveFields) {
          if (encryptedData[field]) {
            try {
              const decrypted = this.cryptoService.decrypt(encryptedData[field])
              if (decrypted) {
                sessionData[field] = decrypted as string
              }
            } catch (error) {
              this.logger.warn(`[findById] Failed to decrypt ${field} for session ${sessionId}, using raw value`)
            }
          }
        }
      } catch (error) {
        this.logger.error(`[findById] Error retrieving or decrypting session data: ${error.message}`, error.stack)
        return null
      }
    } else {
      // Không sử dụng mã hóa, lấy dữ liệu thông thường
      try {
        sessionData = await this.redisService.hgetall(key)
        if (!sessionData || Object.keys(sessionData).length === 0) {
          this.logger.debug(`[findById] No session found for ID ${sessionId}`)
          return null
        }
      } catch (error) {
        this.logger.error(`[findById] Error retrieving session data: ${error.message}`, error.stack)
        return null
      }
    }

    return this.mapRedisDataToSession(sessionData, sessionId)
  }

  /**
   * Tìm tất cả session của user
   */
  async findSessionsByUserId(userId: number, options: SessionPaginationOptions): Promise<SessionPaginationResult> {
    const { page = 1, limit = 10 } = options

    const allKeys = await this.redisService.keys(RedisKeyManager.sessionKey('*'))
    const allSessions: Session[] = []

    // Sử dụng batch process để lấy nhiều session cùng một lúc
    const batchSize = 10 // Số session xử lý trong một batch
    const batches: string[][] = []

    for (let i = 0; i < allKeys.length; i += batchSize) {
      const batchKeys = allKeys.slice(i, i + batchSize)
      batches.push(batchKeys)
    }

    for (const batch of batches) {
      const operations: RedisOperation[] = batch.map((key) => ({
        command: 'hgetall',
        args: [key]
      }))

      const results = await this.redisService.batchProcess(operations)

      // Xử lý kết quả của mỗi session trong batch
      for (let i = 0; i < results.length; i++) {
        const sessionData = results[i]
        if (!sessionData) continue

        const sessionId = batch[i].replace(RedisKeyManager.sessionKey('').replace('*', ''), '')

        if (sessionData.userId === userId.toString()) {
          const sessionObj = this.mapRedisDataToSession(sessionData, sessionId)
          if (sessionObj) {
            allSessions.push(sessionObj)
          }
        }
      }
    }

    this.logger.debug(`[findSessionsByUserId] Found ${allSessions.length} sessions for user ${userId}`)

    // Sắp xếp theo lastActive giảm dần (mới nhất trước)
    allSessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())

    // Tính toán phân trang
    const startIndex = (page - 1) * limit
    const endIndex = startIndex + limit
    const paginatedSessions = allSessions.slice(startIndex, endIndex)

    return {
      data: paginatedSessions,
      total: allSessions.length,
      page,
      limit,
      totalPages: Math.ceil(allSessions.length / limit)
    }
  }

  /**
   * Map dữ liệu Redis sang đối tượng Session
   */
  private mapRedisDataToSession(redisData: Record<string, string>, sessionId: string): Session | null {
    try {
      // Convert data types
      const userId = parseInt(redisData.userId, 10)
      const deviceId = parseInt(redisData.deviceId, 10)
      const createdAt = new Date(parseInt(redisData.createdAt, 10))
      const expiresAt = new Date(parseInt(redisData.expiresAt, 10))
      const lastActive = new Date(parseInt(redisData.lastActive, 10))
      const isActive = redisData.isActive === '1'

      // Create session object
      const session: Session = {
        id: sessionId,
        userId,
        deviceId,
        createdAt,
        expiresAt,
        lastActive,
        ipAddress: redisData.ipAddress,
        userAgent: redisData.userAgent,
        isActive
      }

      return session
    } catch (error) {
      this.logger.error(`[mapRedisDataToSession] Error mapping Redis data to session: ${error.message}`, error.stack)
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

    // Chuẩn bị dữ liệu phiên
    const sessionRedisData: Record<string, string> = {
      userId: userId.toString(),
      deviceId: deviceId.toString(),
      createdAt: createdAtTimestamp.toString(),
      expiresAt: expiresAtTimestamp.toString(),
      lastActive: lastActiveTimestamp.toString(),
      isActive: '1'
    }

    const key = RedisKeyManager.sessionKey(id)
    const ttlInSeconds = Math.floor((expiresAtTimestamp - createdAtTimestamp) / 1000) || 86400 // Mặc định 1 ngày nếu TTL không hợp lệ

    // Sử dụng batch process
    const operations: RedisOperation[] = []

    // Nếu có CryptoService, mã hóa các trường nhạy cảm
    if (this.cryptoService) {
      // Mã hóa các trường nhạy cảm
      sessionRedisData.ipAddress = this.cryptoService.encrypt(ipAddress)
      sessionRedisData.userAgent = this.cryptoService.encrypt(userAgent)

      operations.push({
        command: 'hset',
        args: [key, sessionRedisData]
      })

      operations.push({
        command: 'expire',
        args: [key, ttlInSeconds]
      })

      this.logger.debug(`[createSession] Redis key: ${key}, Session data stored with encryption`)

      await this.redisService.batchProcess(operations)
    } else {
      // Không mã hóa, lưu trữ như bình thường
      sessionRedisData.ipAddress = ipAddress
      sessionRedisData.userAgent = userAgent

      operations.push({
        command: 'hset',
        args: [key, sessionRedisData]
      })

      operations.push({
        command: 'expire',
        args: [key, ttlInSeconds]
      })

      this.logger.debug(`[createSession] Redis key: ${key}, Session data to store: ${JSON.stringify(sessionRedisData)}`)

      await this.redisService.batchProcess(operations)
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
    const key = RedisKeyManager.sessionKey(sessionId)
    const now = Date.now()

    await this.redisService.hset(key, {
      lastActive: now.toString()
    })
  }

  /**
   * Xóa một session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = RedisKeyManager.sessionKey(sessionId)
    await this.redisService.del(key)
  }

  /**
   * Xóa tất cả session của user
   */
  async deleteAllUserSessions(userId: number, excludeSessionId?: string): Promise<{ count: number }> {
    const allKeysPattern = RedisKeyManager.sessionKey('*')
    this.logger.debug(`[deleteAllUserSessions] Fetching all session keys with pattern: ${allKeysPattern}`)
    const keys = await this.redisService.keys(allKeysPattern)
    let count = 0

    // Sử dụng batch process để xử lý các sessions
    const operations: RedisOperation[] = []
    const sessionsToDelete: string[] = []

    this.logger.debug(
      `[deleteAllUserSessions] Found ${keys.length} total session keys. Filtering for userId: ${userId}.`
    )

    // Đầu tiên lấy tất cả thông tin session trong 1 batch
    const allSessions: SessionInRedis[] = []
    const batchSize = 20 // Số session xử lý trong một batch
    const batches: string[][] = []

    for (let i = 0; i < keys.length; i += batchSize) {
      const batchKeys = keys.slice(i, i + batchSize)
      batches.push(batchKeys)
    }

    for (const batch of batches) {
      const batchOperations: RedisOperation[] = batch.map((key) => ({
        command: 'hgetall',
        args: [key]
      }))

      const results = await this.redisService.batchProcess(batchOperations)

      for (let i = 0; i < results.length; i++) {
        const sessionData = results[i]
        if (sessionData) {
          allSessions.push({
            key: batch[i],
            data: sessionData
          })
        }
      }
    }

    // Bây giờ lọc ra các session cần xóa
    for (const session of allSessions) {
      try {
        const sessionPrefix = RedisKeyManager.sessionKey('').replace('*', '')
        const sessionIdFromKey = session.key.replace(sessionPrefix, '')

        // Skip session cần loại trừ
        if (excludeSessionId && sessionIdFromKey === excludeSessionId) {
          this.logger.debug(`[deleteAllUserSessions] Skipping excluded session: ${sessionIdFromKey}`)
          continue
        }

        const sessionUserId = session.data.userId

        if (sessionUserId && parseInt(sessionUserId, 10) === userId) {
          this.logger.debug(
            `[deleteAllUserSessions] Deleting session: ${session.key} for userId: ${userId} (sessionId: ${sessionIdFromKey})`
          )
          sessionsToDelete.push(session.key)
          count++
        } else if (sessionUserId) {
          this.logger.debug(
            `[deleteAllUserSessions] Skipping session: ${session.key} (belongs to userId: ${sessionUserId})`
          )
        } else {
          this.logger.warn(`[deleteAllUserSessions] Session key ${session.key} does not have a userId field. Skipping.`)
        }
      } catch (error) {
        this.logger.error(
          `[deleteAllUserSessions] Error processing key ${session.key} for deletion: ${error.message}`,
          error.stack
        )
      }
    }

    // Thực hiện xóa các sessions trong một batch nếu có
    if (sessionsToDelete.length > 0) {
      await this.redisService.del(sessionsToDelete)
    }

    this.logger.debug(`[deleteAllUserSessions] Deleted ${count} sessions for userId: ${userId}`)
    return { count }
  }

  // Thêm phương thức để lưu trữ lịch sử phiên bị thu hồi
  async archiveSession(sessionId: string): Promise<void> {
    // Lấy dữ liệu phiên hiện tại
    const sessionKey = RedisKeyManager.sessionKey(sessionId)
    const sessionData = await this.redisService.hgetall(sessionKey)

    if (!sessionData) {
      this.logger.warn(`[archiveSession] Session ${sessionId} not found for archiving`)
      return
    }

    // Lưu trữ như một bản lưu trữ
    const archiveKey = RedisKeyManager.sessionArchivedKey(sessionId)

    // Sử dụng mã hóa nếu có CryptoService
    if (this.cryptoService) {
      await this.redisService.setEncrypted(archiveKey, sessionData, LOGIN_HISTORY_TTL)
      this.logger.debug(`[archiveSession] Session ${sessionId} archived with encryption`)
    } else {
      await this.redisService.hset(archiveKey, sessionData)
      await this.redisService.expire(archiveKey, LOGIN_HISTORY_TTL)
      this.logger.debug(`[archiveSession] Session ${sessionId} archived successfully`)
    }
  }
}
