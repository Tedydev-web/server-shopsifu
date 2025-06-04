import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { CookieNames } from 'src/shared/constants/auth.constant'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  PendingLinkTokenPayload,
  PendingLinkTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { ITokenService } from 'src/shared/types/auth.types'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import {
  DEVICE_REVOKE_HISTORY_TTL,
  DEVICE_REVERIFICATION_TTL,
  DEVICE_REVERIFY_KEY_PREFIX,
  SESSION_INVALIDATED_KEY_PREFIX,
  REVOKE_HISTORY_KEY_PREFIX
} from '../../constants/auth.constants'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { CryptoService } from 'src/shared/services/crypto.service'

@Injectable()
export class TokenService implements ITokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly cryptoService?: CryptoService
  ) {}

  /**
   * Tạo access token
   */
  signAccessToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>): string {
    return this.jwtService.sign(payload, {
      expiresIn: this.configService.get('auth.accessToken.expiresIn', '1h')
    })
  }

  /**
   * Tạo refresh token
   */
  signRefreshToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>): string {
    return this.jwtService.sign(payload, {
      expiresIn: this.configService.get('auth.refreshToken.expiresIn', '7d')
    })
  }

  /**
   * Tạo Short-Lived Token
   */
  signShortLivedToken(payload: any): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get('SLT_JWT_SECRET'),
      expiresIn: this.configService.get('SLT_JWT_EXPIRES_IN', '5m')
    })
  }

  /**
   * Xác minh access token
   */
  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token)

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.isAccessTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidAccessToken()
      }

      return payload
    } catch (error) {
      this.logger.error(`Token validation error: ${error.message}`)
      throw AuthError.InvalidAccessToken()
    }
  }

  /**
   * Xác minh refresh token
   */
  async verifyRefreshToken(token: string): Promise<AccessTokenPayload> {
    return this.verifyAccessToken(token)
  }

  /**
   * Tạo pending link token
   */
  signPendingLinkToken(payload: PendingLinkTokenPayloadCreate): string {
    return this.jwtService.sign(
      {
        ...payload,
        jti: `pending_link_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
      },
      {
        expiresIn: this.configService.get('auth.oauth.pendingLinkExpiresIn', '15m')
      }
    )
  }

  /**
   * Xác minh pending link token
   */
  async verifyPendingLinkToken(token: string): Promise<PendingLinkTokenPayload> {
    try {
      return await this.jwtService.verifyAsync<PendingLinkTokenPayload>(token)
    } catch (error) {
      this.logger.error(`Pending link token validation error: ${error.message}`)
      throw error
    }
  }

  /**
   * Lấy token từ request
   */
  extractTokenFromRequest(req: Request): string | null {
    // Ưu tiên lấy từ Authorization header
    const authHeader = req.headers.authorization
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7)
    }

    // Nếu không có, lấy từ cookie
    return req.cookies?.access_token || null
  }

  /**
   * Lấy refresh token từ request
   */
  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.refresh_token || null
  }

  /**
   * Đánh dấu access token là đã vô hiệu hóa
   */
  async invalidateAccessTokenJti(accessTokenJti: string, accessTokenExp: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000)
    const ttl = accessTokenExp - now

    if (ttl > 0) {
      const key = RedisKeyManager.accessTokenBlacklistKey(accessTokenJti)
      await this.redisService.set(key, '1', 'EX', ttl)
    }
  }

  /**
   * Đánh dấu refresh token là đã vô hiệu hóa
   */
  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void> {
    const key = RedisKeyManager.refreshTokenBlacklistKey(refreshTokenJti)
    await this.redisService.set(
      key,
      sessionId,
      'EX',
      this.configService.get('auth.refreshToken.expiresInSeconds', 7 * 24 * 60 * 60)
    )
  }

  /**
   * Kiểm tra access token có trong blacklist không
   */
  async isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.accessTokenBlacklistKey(accessTokenJti)
    const result = await this.redisService.exists(key)
    return result > 0
  }

  /**
   * Kiểm tra refresh token có trong blacklist không
   */
  async isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.refreshTokenBlacklistKey(refreshTokenJti)
    const result = await this.redisService.exists(key)
    return result > 0
  }

  /**
   * Tìm session ID từ refresh token
   */
  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
    const key = RedisKeyManager.refreshTokenBlacklistKey(refreshTokenJti)
    return this.redisService.get(key)
  }

  /**
   * Đánh dấu refresh token đã được sử dụng
   */
  async markRefreshTokenJtiAsUsed(
    refreshTokenJti: string,
    sessionId: string,
    ttlSeconds: number = 30 * 24 * 60 * 60
  ): Promise<boolean> {
    const key = RedisKeyManager.refreshTokenUsedKey(refreshTokenJti)
    const result = await this.redisService.set(key, sessionId, 'EX', ttlSeconds)
    return !!result
  }

  /**
   * Vô hiệu hóa một session cụ thể
   * @param sessionId ID của session cần vô hiệu hóa
   * @param reason Lý do vô hiệu hóa
   * @returns Promise<void>
   */
  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN'): Promise<void> {
    this.logger.debug(`[invalidateSession] Invalidating session: ${sessionId} with reason: ${reason}`)

    // Xác định khóa vô hiệu hóa phiên
    const invalidatedSessionKey = RedisKeyManager.sessionInvalidatedKey(sessionId)

    try {
      // Lưu lý do vô hiệu hóa
      await this.redisService.set(invalidatedSessionKey, reason, 'EX', DEVICE_REVERIFICATION_TTL)
      this.logger.debug(`[invalidateSession] Session ${sessionId} invalidated with TTL: ${DEVICE_REVERIFICATION_TTL}`)

      // Lưu thông tin về thiết bị để yêu cầu xác thực lại trong tương lai
      try {
        // Lấy thông tin phiên từ Redis
        const sessionKey = RedisKeyManager.sessionKey(sessionId)
        const sessionData = await this.redisService.hgetall(sessionKey)

        if (sessionData && sessionData.userId && sessionData.deviceId) {
          const userId = parseInt(sessionData.userId, 10)
          const deviceId = parseInt(sessionData.deviceId, 10)

          // Đánh dấu thiết bị cần xác thực lại
          await this.markDeviceForReverification(userId, deviceId, reason)

          // Lưu trữ phiên bị thu hồi
          await this.archiveRevokedSession(sessionId, sessionData, reason)
        }
      } catch (error) {
        this.logger.error(`[invalidateSession] Failed to process device reverification: ${error.message}`, error.stack)
      }
    } catch (error) {
      this.logger.error(`[invalidateSession] Failed to invalidate session ${sessionId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Đánh dấu thiết bị để yêu cầu xác thực lại trong lần đăng nhập tiếp theo
   */
  async markDeviceForReverification(userId: number, deviceId: number, reason: string): Promise<void> {
    this.logger.debug(`[markDeviceForReverification] Marking device ${deviceId} for user ${userId} for reverification`)

    const deviceReverificationKey = RedisKeyManager.deviceReverifyKey(userId, deviceId)
    const data = {
      userId,
      deviceId,
      reason,
      timestamp: Date.now()
    }

    try {
      // Lưu trữ dữ liệu mã hóa nếu CryptoService khả dụng
      if (this.cryptoService) {
        await this.redisService.setEncrypted(deviceReverificationKey, data, DEVICE_REVERIFICATION_TTL)
      } else {
        await this.redisService.setJson(deviceReverificationKey, data, DEVICE_REVERIFICATION_TTL)
      }

      this.logger.debug(
        `[markDeviceForReverification] Device ${deviceId} marked for reverification with TTL: ${DEVICE_REVERIFICATION_TTL}`
      )
    } catch (error) {
      this.logger.error(`[markDeviceForReverification] Failed to mark device: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Kiểm tra xem thiết bị có yêu cầu xác thực lại hay không
   */
  async checkDeviceNeedsReverification(userId: number, deviceId: number): Promise<boolean> {
    const deviceReverificationKey = RedisKeyManager.deviceReverifyKey(userId, deviceId)

    try {
      const exists = await this.redisService.exists(deviceReverificationKey)
      return exists > 0
    } catch (error) {
      this.logger.error(`[checkDeviceNeedsReverification] Failed to check device: ${error.message}`, error.stack)
      return false
    }
  }

  /**
   * Xóa yêu cầu xác thực lại cho thiết bị sau khi đã xác thực thành công
   */
  async clearDeviceReverification(userId: number, deviceId: number): Promise<void> {
    const deviceReverificationKey = RedisKeyManager.deviceReverifyKey(userId, deviceId)

    try {
      await this.redisService.del(deviceReverificationKey)
      this.logger.debug(
        `[clearDeviceReverification] Cleared reverification requirement for device ${deviceId}, user ${userId}`
      )
    } catch (error) {
      this.logger.error(
        `[clearDeviceReverification] Failed to clear device reverification: ${error.message}`,
        error.stack
      )
    }
  }

  /**
   * Lưu trữ thông tin phiên bị thu hồi để phân tích sau này
   */
  private async archiveRevokedSession(sessionId: string, sessionData: any, reason: string): Promise<void> {
    if (!sessionData) return

    try {
      // Lưu trữ lịch sử thu hồi
      const historyKey = RedisKeyManager.sessionRevokeHistoryKey(sessionId)
      const historyData = {
        ...sessionData,
        revokeTimestamp: Date.now(),
        reason
      }

      // Lưu trữ dữ liệu mã hóa nếu CryptoService khả dụng
      if (this.cryptoService) {
        await this.redisService.setEncrypted(historyKey, historyData, DEVICE_REVOKE_HISTORY_TTL)
      } else {
        await this.redisService.setJson(historyKey, historyData, DEVICE_REVOKE_HISTORY_TTL)
      }

      this.logger.debug(`[archiveRevokedSession] Archived session ${sessionId} revocation history`)
    } catch (error) {
      this.logger.error(`[archiveRevokedSession] Error archiving session: ${error.message}`, error.stack)
    }
  }

  /**
   * Kiểm tra xem session có bị vô hiệu hóa không
   * @param sessionId ID của session cần kiểm tra
   * @returns Promise<boolean> true nếu bị vô hiệu hóa, false nếu không
   */
  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    if (!sessionId) {
      this.logger.warn('[isSessionInvalidated] Session ID không hợp lệ')
      return true
    }

    try {
      // Kiểm tra session trong blacklist
      const key = RedisKeyManager.sessionInvalidatedKey(sessionId)
      const exists = await this.redisService.exists(key)

      if (exists) {
        this.logger.debug(`[isSessionInvalidated] Session ${sessionId} đã bị vô hiệu hóa`)
        return true
      }

      this.logger.debug(`[isSessionInvalidated] Session ${sessionId} không bị vô hiệu hóa`)
      return false
    } catch (error) {
      this.logger.error(`[isSessionInvalidated] Lỗi khi kiểm tra session ${sessionId}: ${error.message}`)
      return false
    }
  }

  /**
   * Vô hiệu hóa tất cả session của một user
   * @param userId ID của người dùng
   * @param reason Lý do vô hiệu hóa
   * @param sessionIdToExclude ID session cần loại trừ (thường là session hiện tại)
   * @returns Promise<void>
   */
  async invalidateAllUserSessions(
    userId: number,
    reason: string = 'UNKNOWN_BULK_INVALIDATION',
    sessionIdToExclude?: string
  ): Promise<void> {
    if (!userId) {
      this.logger.warn('[invalidateAllUserSessions] Không thể vô hiệu hóa session với userId rỗng')
      return
    }

    try {
      // Sử dụng batch processing để cải thiện hiệu suất
      interface RedisOperation {
        command: string
        args: any[]
      }

      const operations: RedisOperation[] = []

      // 1. Lưu thông tin trong Redis để tra cứu nhanh
      const userKey = RedisKeyManager.invalidatedUserKey(userId)

      // Thêm timestamp để biết khi nào tất cả sessions bị vô hiệu hóa
      const invalidationData = JSON.stringify({
        timestamp: Date.now(),
        reason,
        excludeSessionId: sessionIdToExclude
      })

      // Lưu với TTL 30 ngày (chuẩn bị thêm vào batch)
      operations.push({
        command: 'set',
        args: [userKey, invalidationData, 'EX', 30 * 24 * 60 * 60]
      })

      // 2. Thêm vào danh sách user có session bị vô hiệu hóa hàng loạt để kiểm tra nhanh
      operations.push({
        command: 'sadd',
        args: ['invalidated:users', userId.toString()]
      })

      // Thực thi tất cả các thao tác trong một lệnh pipeline
      await this.redisService.batchProcess(operations)

      // 3. Publish sự kiện để các instances khác có thể cập nhật cache nội bộ
      const eventData = JSON.stringify({
        userId,
        reason,
        excludeSessionId: sessionIdToExclude,
        timestamp: Date.now()
      })
      await this.redisService.publish('user:sessions:invalidated', eventData)

      this.logger.debug(
        `[invalidateAllUserSessions] Tất cả sessions của user ${userId} đã bị vô hiệu hóa với lý do: ${reason}`
      )
    } catch (error) {
      this.logger.error(
        `[invalidateAllUserSessions] Lỗi khi vô hiệu hóa tất cả sessions của user ${userId}: ${error.message}`,
        error.stack
      )
      throw error
    }
  }
}
