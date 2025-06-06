import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import {
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  PendingLinkTokenPayload,
  PendingLinkTokenPayloadCreate
} from 'src/shared/types/jwt.type'
import { ConfigService } from '@nestjs/config'
import { ITokenService } from 'src/shared/types/auth.types'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { CryptoService } from 'src/shared/services/crypto.service'
import { AuthError } from 'src/routes/auth/auth.error'
import {
  DEVICE_REVOKE_HISTORY_TTL,
  DEVICE_REVERIFICATION_TTL,
  DEVICE_REVERIFY_KEY_PREFIX
} from 'src/shared/constants/auth.constants'
import { DeviceRepository, SessionRepository } from 'src/shared/repositories/auth'
import { v4 as uuidv4 } from 'uuid'
import { SessionsService } from 'src/routes/auth/modules/sessions/sessions.service'
import { DeviceService } from 'src/shared/services/auth/device.service'

@Injectable()
export class TokenService implements ITokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly deviceRepository: DeviceRepository,
    private readonly sessionRepository: SessionRepository,
    private readonly cryptoService?: CryptoService,
    private readonly sessionsService?: SessionsService,
    private readonly deviceService?: DeviceService
  ) {}

  /**
   * Tạo access token
   */
  async generateAccessToken(userId: number, expiresIn?: string): Promise<string> {
    const tokenJti = `access_${Date.now()}_${uuidv4().substring(0, 8)}`
    const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      userId,
      jti: tokenJti,
      type: 'ACCESS'
    }
    return Promise.resolve(this.signAccessToken(payload))
  }

  /**
   * Tạo refresh token
   */
  async generateRefreshToken(userId: number, rememberMe?: boolean): Promise<string> {
    const tokenJti = `refresh_${Date.now()}_${uuidv4().substring(0, 8)}`
    const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      userId,
      jti: tokenJti,
      type: 'REFRESH'
    }

    const expiresIn = rememberMe
      ? this.configService.get('auth.refreshToken.extendedExpiresIn', '30d')
      : this.configService.get('auth.refreshToken.expiresIn', '7d')

    return Promise.resolve(
      this.jwtService.sign(payload, {
        secret: this.configService.get('REFRESH_JWT_SECRET', this.configService.get('JWT_SECRET')),
        expiresIn
      })
    )
  }

  /**
   * Xác minh access token
   */
  async validateAccessToken(token: string): Promise<any> {
    try {
      return await this.verifyAccessToken(token)
    } catch (error) {
      this.logger.error(`AccessToken validation error: ${error.message}`)
      throw AuthError.InvalidAccessToken()
    }
  }

  /**
   * Xác minh refresh token
   */
  async validateRefreshToken(token: string): Promise<any> {
    try {
      const payload = await this.verifyRefreshToken(token)

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      return payload
    } catch (error) {
      this.logger.error(`RefreshToken validation error: ${error.message}`)
      throw AuthError.InvalidRefreshToken()
    }
  }

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
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.configService.get('JWT_SECRET')
      })

      // Kiểm tra token có trong blacklist không
      const isBlacklisted = await this.isAccessTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidAccessToken()
      }

      return payload
    } catch (error) {
      this.logger.error(`Token validation error: ${error.message}`)
      if (error instanceof AuthError) throw error
      throw AuthError.InvalidAccessToken()
    }
  }

  /**
   * Xác minh refresh token
   */
  async verifyRefreshToken(token: string): Promise<AccessTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.configService.get('REFRESH_JWT_SECRET', this.configService.get('JWT_SECRET'))
      })

      return payload
    } catch (error) {
      this.logger.error(`Refresh token validation error: ${error.message}`)
      if (error instanceof AuthError) throw error
      if (error.name === 'TokenExpiredError') {
        throw AuthError.RefreshTokenExpired()
      } else if (error.name === 'JsonWebTokenError') {
        throw AuthError.InvalidRefreshToken()
      }
      throw AuthError.InvalidRefreshToken()
    }
  }

  /**
   * Tạo pending link token
   */
  signPendingLinkToken(payload: PendingLinkTokenPayloadCreate): string {
    return this.jwtService.sign(payload, {
      expiresIn: this.configService.get('auth.pendingLinkToken.expiresIn', '15m')
    })
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
    try {
      await this.redisService.set(key, sessionId, 'EX', ttlSeconds)
      return true
    } catch (error) {
      this.logger.error(`Lỗi khi đánh dấu refresh token đã sử dụng: ${error.message}`, error.stack)
      return false
    }
  }

  /**
   * Vô hiệu hóa một session cụ thể.
   * @deprecated Sử dụng SessionsService.invalidateSession thay thế
   */
  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN'): Promise<void> {
    if (this.sessionsService) {
      await this.sessionsService.invalidateSession(sessionId, reason)
      return
    }

    // Fallback nếu SessionsService chưa được inject
    this.logger.warn(`[invalidateSession] SessionsService not available. Using deprecated implementation.`)

    try {
      const isAlreadyInvalidated = await this.isSessionInvalidated(sessionId)
      if (isAlreadyInvalidated) {
        this.logger.debug(`[invalidateSession] Session ${sessionId} is already invalidated. Skipping.`)
        return
      }

      const sessionKey = RedisKeyManager.sessionKey(sessionId)
      const sessionData = await this.redisService.hgetall(sessionKey)

      if (!sessionData || Object.keys(sessionData).length === 0) {
        this.logger.warn(
          `[invalidateSession] No data found for session ${sessionId} in Redis. Cannot process full invalidation logic. Marking as invalidated.`
        )
        // Dù không có data, vẫn đánh dấu là invalidated để isSessionInvalidated() trả về true
        const invalidatedKeyFallback = RedisKeyManager.sessionInvalidatedKey(sessionId)
        await this.redisService.set(
          invalidatedKeyFallback,
          reason,
          'EX',
          this.configService.get<number>('auth.session.invalidatedTtl', 7 * 24 * 60 * 60)
        )
        return
      }

      const userId = parseInt(sessionData.userId, 10)
      const deviceId = parseInt(sessionData.deviceId, 10)

      // Lưu lại thông tin session bị vô hiệu hoá
      await this.archiveRevokedSession(sessionId, sessionData, reason)

      // Đánh dấu session là đã vô hiệu hoá
      const invalidatedKey = RedisKeyManager.sessionInvalidatedKey(sessionId)
      await this.redisService.set(
        invalidatedKey,
        reason,
        'EX',
        this.configService.get<number>('auth.session.invalidatedTtl', 7 * 24 * 60 * 60)
      )

      // Xoá session data khỏi Redis
      await this.redisService.del(sessionKey)
      this.logger.log(`Session ${sessionId} data deleted from Redis. Reason: ${reason}`)

      // Xoá session khỏi các index
      if (userId) {
        await this.redisService.srem(RedisKeyManager.userSessionsKey(userId), sessionId)
        this.logger.debug(`Session ${sessionId} removed from user index for user ${userId}.`)
      }
      if (deviceId) {
        await this.redisService.srem(RedisKeyManager.deviceSessionsKey(deviceId), sessionId)
        this.logger.debug(`Session ${sessionId} removed from device index for device ${deviceId}.`)
      }

      if (deviceId && userId && this.sessionRepository && this.deviceRepository) {
        const deviceSessionsKey = RedisKeyManager.deviceSessionsKey(deviceId)
        const activeSessionIdsOnDevice = await this.redisService.smembers(deviceSessionsKey)

        let hasOtherActiveSessionsOnDevice = false
        if (activeSessionIdsOnDevice && activeSessionIdsOnDevice.length > 0) {
          for (const activeSessionId of activeSessionIdsOnDevice) {
            if (activeSessionId === sessionId) continue // Bỏ qua session vừa bị revoke
            const activeSessionData = await this.redisService.hgetall(RedisKeyManager.sessionKey(activeSessionId))
            if (activeSessionData && activeSessionData.isActive === '1') {
              hasOtherActiveSessionsOnDevice = true
              break
            }
          }
        }

        if (!hasOtherActiveSessionsOnDevice) {
          this.logger.log(`Session ${sessionId} was the last active session on device ${deviceId}. Untrusting device.`)
          await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
        } else {
          // Nếu không phải session cuối cùng, đặt cờ yêu cầu xác minh lại cho thiết bị
          const reverifyKey = RedisKeyManager.customKey('device:needs_reverify_after_revoke', deviceId.toString())
          await this.redisService.set(reverifyKey, 'true', 'EX', 300) // 5 phút TTL
          this.logger.debug(
            `Device ${deviceId} marked for reverification after session ${sessionId} revoke. Key: ${reverifyKey}`
          )
        }
      } else {
        this.logger.warn(
          `[invalidateSession] SessionRepository or DeviceRepository not available. Skipping device untrust/re-verify logic for session ${sessionId}.`
        )
      }

      this.logger.log(`Session ${sessionId} has been invalidated successfully. Reason: ${reason}`)
    } catch (error) {
      this.logger.error(`Error invalidating session ${sessionId}: ${error.message}`, error.stack)
    }
  }
}
