import { Injectable, Logger, Inject } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { LOGIN_HISTORY_TTL } from 'src/routes/auth/shared/constants/auth.constants'
import { RedisService } from 'src/providers/redis/redis.service'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { CryptoService } from 'src/routes/auth/shared/services/common/crypto.service'
import { IPrisma, PrismaTransactionClient } from 'src/shared/types/prisma.type'
import { Prisma } from '@prisma/client'

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

    const userSessionIdsKey = RedisKeyManager.userSessionsKey(userId)
    // Lấy danh sách các session ID từ SET của user
    const sessionIds = await this.redisService.smembers(userSessionIdsKey)

    if (!sessionIds || sessionIds.length === 0) {
      return {
        data: [],
        total: 0,
        page,
        limit,
        totalPages: 0
      }
    }

    const allSessions: Session[] = []
    const operations: RedisOperation[] = sessionIds.map((id) => ({
      command: 'hgetall',
      args: [RedisKeyManager.sessionKey(id)]
    }))

    // Sử dụng batchProcess để lấy dữ liệu của tất cả các session
    const results = await this.redisService.batchProcess(operations)

    for (let i = 0; i < results.length; i++) {
      const sessionData = results[i]
      const sessionId = sessionIds[i] // ID tương ứng với kết quả

      if (sessionData && Object.keys(sessionData).length > 0 && sessionData.userId === userId.toString()) {
        // Kiểm tra sessionData.userId vì smembers chỉ trả về ID, HGETALL mới có chi tiết
        // và để đảm bảo an toàn hơn, mặc dù về lý thuyết userSessionsKey đã đúng user
        const sessionObj = this.mapRedisDataToSession(sessionData, sessionId)
        if (sessionObj) {
          allSessions.push(sessionObj)
        }
      } else if (sessionData && Object.keys(sessionData).length > 0 && sessionData.userId !== userId.toString()) {
        // Trường hợp hiếm: session ID có trong set của user này nhưng dữ liệu HASH lại của user khác?
        // Hoặc session ID không hợp lệ. Cần ghi log và có thể xóa khỏi set của user.
        this.logger.warn(
          `[findSessionsByUserId] Session ID ${sessionId} from user set ${userSessionIdsKey} ` +
            `has mismatched userId in its HASH data (${sessionData.userId} vs ${userId}). ` +
            `Consider removing it from the set.`
        )
        // await this.redisService.srem(userSessionIdsKey, sessionId); // Cân nhắc tự động dọn dẹp
      } else if (!sessionData || Object.keys(sessionData).length === 0) {
        // Session ID có trong set nhưng không tìm thấy HASH data (có thể đã hết hạn hoặc bị xóa không đúng cách)
        this.logger.warn(
          `[findSessionsByUserId] Session ID ${sessionId} from user set ${userSessionIdsKey} ` +
            `did not have corresponding HASH data. Consider removing it from the set.`
        )
        // await this.redisService.srem(userSessionIdsKey, sessionId); // Cân nhắc tự động dọn dẹp
      }
    }

    this.logger.debug(
      `[findSessionsByUserId] Found ${allSessions.length} sessions for user ${userId} after fetching details.`
    )

    // Sắp xếp theo lastActive giảm dần (mới nhất trước)
    allSessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())

    // Tính toán phân trang
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

      // Add device data if available
      if (redisData.deviceName) {
        session.device = {
          id: deviceId,
          name: redisData.deviceName,
          isTrusted: redisData.deviceTrusted === '1'
        }
      }

      return session
    } catch (error) {
      this.logger.error(`Error mapping Redis data to Session: ${error.message}`)
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
    const now = new Date()
    const key = RedisKeyManager.sessionKey(id)

    // Chuẩn bị dữ liệu cơ bản
    const basicSessionData: Record<string, string> = {
      userId: userId.toString(),
      deviceId: deviceId.toString(),
      createdAt: now.getTime().toString(),
      expiresAt: expiresAt.getTime().toString(),
      lastActive: now.getTime().toString(),
      isActive: '1'
    }

    // Dữ liệu nhạy cảm có thể được mã hóa
    let sensitiveData: Record<string, string> = {
      ipAddress,
      userAgent
    }

    // Mã hóa dữ liệu nhạy cảm nếu có cryptoService
    if (this.cryptoService) {
      try {
        const encryptedIpAddress = this.cryptoService.encrypt(ipAddress)
        const encryptedUserAgent = this.cryptoService.encrypt(userAgent)

        sensitiveData = {
          ipAddress: encryptedIpAddress,
          userAgent: encryptedUserAgent
        }
      } catch (error) {
        this.logger.warn(`Failed to encrypt session data: ${error.message}. Using plain text.`)
      }
    }

    // Lưu session vào Redis
    try {
      await this.redisService.hset(key, {
        ...basicSessionData,
        ...sensitiveData
      })

      // Thiết lập TTL cho session
      const ttlMilliseconds = expiresAt.getTime() - now.getTime()
      const ttlSeconds = Math.floor(ttlMilliseconds / 1000)
      await this.redisService.expire(key, ttlSeconds > 0 ? ttlSeconds : 3600) // ít nhất 1h

      this.logger.debug(`Session created: ${id} for user ${userId}, expires in ${ttlSeconds} seconds`)

      // Cập nhật danh sách session của user
      await this.addSessionToUserIndex(userId, id)

      // Cập nhật danh sách session của device
      await this.addSessionToDeviceIndex(deviceId, id)

      // Lưu thông tin đăng nhập vào lịch sử nếu cần
      const shouldLogToHistory = true // Flag này có thể được cấu hình
      if (shouldLogToHistory) {
        await this.logSessionToLoginHistory(userId, id, {
          deviceId,
          ipAddress,
          userAgent,
          timestamp: now.getTime()
        })
      }

      // Thêm thông tin device vào session để trả về
      let deviceInfo: { name: string | null; isTrusted: boolean } | null = null
      try {
        deviceInfo = await this.prismaService.device.findUnique({
          where: { id: deviceId },
          select: { name: true, isTrusted: true }
        })
      } catch (error) {
        this.logger.warn(`Failed to fetch device info for device ${deviceId}: ${error.message}`)
      }

      return {
        id,
        userId,
        deviceId,
        createdAt: now,
        expiresAt,
        lastActive: now,
        ipAddress,
        userAgent,
        isActive: true,
        device: deviceInfo
          ? {
              id: deviceId,
              name: deviceInfo.name || null,
              isTrusted: deviceInfo.isTrusted || false
            }
          : undefined
      }
    } catch (error) {
      this.logger.error(`Failed to create session: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Cập nhật thông tin hoạt động mới nhất cho session
   */
  async updateSessionActivity(sessionId: string): Promise<void> {
    try {
      const key = RedisKeyManager.sessionKey(sessionId)
      await this.redisService.hset(key, 'lastActive', Date.now().toString())
      this.logger.debug(`Updated activity for session ${sessionId}`)
    } catch (error) {
      this.logger.error(`Error updating session activity: ${error.message}`)
    }
  }

  /**
   * Xóa một session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const session = await this.findById(sessionId) // Lấy thông tin session trước khi xóa
    if (session) {
      await this.archiveSession(sessionId) // Lưu trữ trước khi xóa
      // Xóa session khỏi chỉ mục user và device
      await this.redisService.srem(RedisKeyManager.userSessionsKey(session.userId), sessionId)
      await this.redisService.srem(RedisKeyManager.deviceSessionsKey(session.deviceId), sessionId)
    }
    const key = RedisKeyManager.sessionKey(sessionId)
    await this.redisService.del(key)
    this.logger.debug(`Session ${sessionId} deleted and removed from indexes`)
  }

  /**
   * Xóa tất cả session của một user
   */
  async deleteAllUserSessions(userId: number, excludeSessionId?: string): Promise<{ count: number }> {
    const userSessionIdsKey = RedisKeyManager.userSessionsKey(userId)
    const sessionIdsToDelete = await this.redisService.smembers(userSessionIdsKey)

    if (!sessionIdsToDelete || sessionIdsToDelete.length === 0) {
      this.logger.debug(`[deleteAllUserSessions] No sessions found for user ${userId} in index ${userSessionIdsKey}`)
      return { count: 0 }
    }

    let deletedCount = 0
    const deleteOperations: RedisOperation[] = []
    const deviceIndexCleanupMap = new Map<number, string[]>() // deviceId -> [sessionIds]

    for (const sessionId of sessionIdsToDelete) {
      if (sessionId === excludeSessionId) {
        continue // Bỏ qua session hiện tại nếu được yêu cầu
      }

      // Lấy thông tin deviceId từ session để dọn dẹp device index sau
      // Điều này giả định rằng chúng ta cần đọc session trước khi xóa để lấy deviceId
      // Nếu không muốn đọc lại, deviceId cần được lưu ở đâu đó hoặc logic dọn device index thay đổi
      const sessionDetails = await this.findById(sessionId) // Tốn kém nếu nhiều session
      // Giải pháp tối ưu hơn có thể là không xóa khỏi device index ở đây, mà để cơ chế khác dọn dẹp
      // Hoặc khi tạo session, lưu {sessionId}:{deviceId} vào một set khác của user.

      await this.archiveSession(sessionId) // Lưu trữ session
      deleteOperations.push({
        command: 'del',
        args: [RedisKeyManager.sessionKey(sessionId)]
      })
      deletedCount++

      if (sessionDetails) {
        const deviceSessions = deviceIndexCleanupMap.get(sessionDetails.deviceId) || []
        deviceSessions.push(sessionId)
        deviceIndexCleanupMap.set(sessionDetails.deviceId, deviceSessions)
      }
    }

    if (deleteOperations.length > 0) {
      await this.redisService.batchProcess(deleteOperations)
      this.logger.debug(`[deleteAllUserSessions] Executed DEL for ${deletedCount} sessions of user ${userId}`)

      // Dọn dẹp user index
      if (!excludeSessionId) {
        // Nếu xóa tất cả, xóa luôn key index của user
        await this.redisService.del(userSessionIdsKey)
        this.logger.debug(`[deleteAllUserSessions] Deleted user session index ${userSessionIdsKey}`)
      } else {
        // Nếu chỉ loại trừ một session, xóa các session đã DEL khỏi set của user
        const sremArgs = sessionIdsToDelete.filter((id) => id !== excludeSessionId)
        if (sremArgs.length > 0) {
          await this.redisService.srem(userSessionIdsKey, sremArgs)
          this.logger.debug(
            `[deleteAllUserSessions] Removed ${sremArgs.length} sessions from index ${userSessionIdsKey}`
          )
        }
      }

      // Dọn dẹp device indexes
      for (const [deviceId, sIds] of deviceIndexCleanupMap) {
        if (sIds.length > 0) {
          await this.redisService.srem(RedisKeyManager.deviceSessionsKey(deviceId), sIds)
          this.logger.debug(
            `[deleteAllUserSessions] Removed ${sIds.length} sessions from device index ${RedisKeyManager.deviceSessionsKey(deviceId)}`
          )
        }
      }
    }

    this.logger.debug(`[deleteAllUserSessions] Processed deletion for user ${userId}. Total deleted: ${deletedCount}`)
    return { count: deletedCount }
  }

  /**
   * Thêm session vào index của user
   */
  private async addSessionToUserIndex(userId: number, sessionId: string): Promise<void> {
    const key = RedisKeyManager.userSessionsKey(userId)
    await this.redisService.sadd(key, sessionId)
  }

  /**
   * Thêm session vào index của device
   */
  private async addSessionToDeviceIndex(deviceId: number, sessionId: string): Promise<void> {
    const key = RedisKeyManager.deviceSessionsKey(deviceId)
    await this.redisService.sadd(key, sessionId)
  }

  /**
   * Lưu thông tin session vào lịch sử đăng nhập
   */
  private async logSessionToLoginHistory(
    userId: number,
    sessionId: string,
    data: {
      deviceId: number
      ipAddress: string
      userAgent: string
      timestamp: number
    }
  ): Promise<void> {
    try {
      const key = RedisKeyManager.userLoginHistoryKey(userId)
      const historyData = {
        sessionId,
        deviceId: data.deviceId,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        timestamp: data.timestamp
      }

      // Sử dụng sorted set với timestamp làm score để sắp xếp theo thời gian
      await this.addToSortedSet(key, data.timestamp, JSON.stringify(historyData))

      // Giữ lại tối đa 50 bản ghi lịch sử cho mỗi user
      await this.removeRangeFromSortedSet(key, 0, -51)

      // Đặt TTL cho lịch sử đăng nhập
      await this.redisService.expire(key, LOGIN_HISTORY_TTL)
    } catch (error) {
      this.logger.error(`Error logging to login history: ${error.message}`)
    }
  }

  /**
   * Lưu trữ thông tin session trước khi xóa
   */
  async archiveSession(sessionId: string): Promise<void> {
    try {
      const session = await this.findById(sessionId)
      if (!session) {
        return
      }
    } catch (error) {
      this.logger.error(`Error archiving session: ${error.message}`)
    }
  }

  /**
   * Vô hiệu hóa session
   */
  async deactivateSession(sessionId: string): Promise<void> {
    try {
      const key = RedisKeyManager.sessionKey(sessionId)
      await this.redisService.hset(key, 'isActive', '0')
      this.logger.debug(`Session ${sessionId} has been deactivated`)
    } catch (error) {
      this.logger.error(`Error deactivating session: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Helper method để thêm item vào sorted set
   */
  private async addToSortedSet(key: string, score: number, value: string): Promise<number> {
    return this.redisService.exec('ZADD', [key, score.toString(), value]) as Promise<number>
  }

  /**
   * Helper method để xóa range từ sorted set
   */
  private async removeRangeFromSortedSet(key: string, start: number, stop: number): Promise<number> {
    return this.redisService.exec('ZREMRANGEBYRANK', [key, start.toString(), stop.toString()]) as Promise<number>
  }
}
