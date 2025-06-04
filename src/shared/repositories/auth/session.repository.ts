import { Injectable, Logger, Inject } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { LOGIN_HISTORY_TTL } from 'src/shared/constants/auth.constants'
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
    await this.archiveSession(sessionId) // Lưu trữ trước khi xóa
    const key = RedisKeyManager.sessionKey(sessionId)
    await this.redisService.del(key)
    this.logger.debug(`Session ${sessionId} deleted`)
  }

  /**
   * Xóa tất cả session của một user
   */
  async deleteAllUserSessions(userId: number, excludeSessionId?: string): Promise<{ count: number }> {
    // Lấy tất cả session keys
    const allKeys = await this.redisService.keys(RedisKeyManager.sessionKey('*'))
    let deletedCount = 0

    // Xử lý theo batch để tránh làm quá tải Redis
    const batchSize = 10
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

      const deleteOperations: RedisOperation[] = []

      // Kiểm tra từng session xem có thuộc về user không
      for (let i = 0; i < results.length; i++) {
        const sessionData = results[i]
        if (!sessionData) continue

        const sessionKey = batch[i]
        const sessionId = sessionKey.replace(RedisKeyManager.sessionKey('').replace('*', ''), '')

        // Nếu session thuộc về user và không phải là session được loại trừ
        if (sessionData.userId === userId.toString() && (!excludeSessionId || sessionId !== excludeSessionId)) {
          // Lưu trữ session trước khi xóa
          await this.archiveSession(sessionId)

          // Thêm vào danh sách xóa
          deleteOperations.push({
            command: 'del',
            args: [sessionKey]
          })

          deletedCount++
        }
      }

      // Xóa các session đã chọn trong batch
      if (deleteOperations.length > 0) {
        await this.redisService.batchProcess(deleteOperations)
      }
    }

    // Xóa indexes nếu không có session nào được giữ lại
    if (!excludeSessionId) {
      await this.redisService.del(RedisKeyManager.userSessionsKey(userId))
    }

    this.logger.debug(`Deleted ${deletedCount} sessions for user ${userId}`)
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

      // Lưu vào bảng session_history trong DB (sử dụng Prisma raw query vì không có model trực tiếp)
      await this.prismaService.$executeRaw`
        INSERT INTO session_history (
          original_session_id, user_id, device_id, ip_address, user_agent, 
          created_at, last_active, expires_at
        ) VALUES (
          ${sessionId}, ${session.userId}, ${session.deviceId}, ${session.ipAddress}, 
          ${session.userAgent}, ${session.createdAt}, ${session.lastActive}, ${session.expiresAt}
        )
      `

      this.logger.debug(`Session ${sessionId} archived to history`)
    } catch (error) {
      this.logger.error(`Error archiving session: ${error.message}`)
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
