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

@Injectable()
export class TokenService implements ITokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly configService: ConfigService
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
      await this.redisService.set(`access_token_blacklist:${accessTokenJti}`, '1', 'EX', ttl)
    }
  }

  /**
   * Đánh dấu refresh token là đã vô hiệu hóa
   */
  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void> {
    await this.redisService.set(
      `refresh_token_blacklist:${refreshTokenJti}`,
      sessionId,
      'EX',
      this.configService.get('auth.refreshToken.expiresInSeconds', 7 * 24 * 60 * 60)
    )
  }

  /**
   * Kiểm tra access token có trong blacklist không
   */
  async isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean> {
    const result = await this.redisService.exists(`access_token_blacklist:${accessTokenJti}`)
    return result > 0
  }

  /**
   * Kiểm tra refresh token có trong blacklist không
   */
  async isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean> {
    const result = await this.redisService.exists(`refresh_token_blacklist:${refreshTokenJti}`)
    return result > 0
  }

  /**
   * Tìm session ID từ refresh token
   */
  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
    return this.redisService.get(`refresh_token_blacklist:${refreshTokenJti}`)
  }

  /**
   * Đánh dấu refresh token đã được sử dụng
   */
  async markRefreshTokenJtiAsUsed(
    refreshTokenJti: string,
    sessionId: string,
    ttlSeconds: number = 30 * 24 * 60 * 60
  ): Promise<boolean> {
    const result = await this.redisService.set(`refresh_token_used:${refreshTokenJti}`, sessionId, 'EX', ttlSeconds)
    return !!result
  }

  /**
   * Vô hiệu hóa một session
   * @param sessionId ID của session cần vô hiệu hóa
   * @param reason Lý do vô hiệu hóa
   * @returns Promise<void>
   */
  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN'): Promise<void> {
    if (!sessionId) {
      this.logger.warn('[invalidateSession] Không thể vô hiệu hóa session với sessionId rỗng')
      return
    }

    try {
      // 1. Thêm session vào blacklist trong Redis với TTL dài (30 ngày)
      const key = `invalidated:session:${sessionId}`
      await this.redisService.set(key, reason, 'EX', 30 * 24 * 60 * 60) // 30 ngày

      // 2. Publish sự kiện để các instances khác có thể cập nhật cache nội bộ
      const eventData = JSON.stringify({ sessionId, reason, timestamp: Date.now() })
      await this.redisService.publish('session:invalidated', eventData)

      this.logger.debug(`[invalidateSession] Session ${sessionId} đã bị vô hiệu hóa với lý do: ${reason}`)
    } catch (error) {
      this.logger.error(`[invalidateSession] Lỗi khi vô hiệu hóa session ${sessionId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Kiểm tra xem session có bị vô hiệu hóa không
   * @param sessionId ID của session cần kiểm tra
   * @returns Promise<boolean> true nếu session đã bị vô hiệu hóa
   */
  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    if (!sessionId) {
      this.logger.warn('[isSessionInvalidated] Không thể kiểm tra session với sessionId rỗng')
      return true // Coi như session không hợp lệ nếu không có sessionId
    }

    try {
      // Kiểm tra trong Redis
      const key = `invalidated:session:${sessionId}`
      const value = await this.redisService.get(key)

      const isInvalidated = value !== null

      if (isInvalidated) {
        this.logger.debug(`[isSessionInvalidated] Session ${sessionId} đã bị vô hiệu hóa với lý do: ${value}`)
      }

      return isInvalidated
    } catch (error) {
      this.logger.error(`[isSessionInvalidated] Lỗi khi kiểm tra session ${sessionId}: ${error.message}`, error.stack)
      // Nếu có lỗi, coi như session hợp lệ để tránh chặn truy cập không đáng có
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
      // 1. Lưu thông tin trong Redis để tra cứu nhanh
      const userKey = `invalidated:user:${userId}`

      // Thêm timestamp để biết khi nào tất cả sessions bị vô hiệu hóa
      const invalidationData = JSON.stringify({
        timestamp: Date.now(),
        reason,
        excludeSessionId: sessionIdToExclude
      })

      // Lưu với TTL 30 ngày
      await this.redisService.set(userKey, invalidationData, 'EX', 30 * 24 * 60 * 60)

      // 2. Thêm vào danh sách user có session bị vô hiệu hóa hàng loạt để kiểm tra nhanh
      await this.redisService.sadd('invalidated:users', userId.toString())

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
