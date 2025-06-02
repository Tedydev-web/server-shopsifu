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
      expiresIn: this.configService.get('auth.sltToken.expiresIn', '10m')
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
   * Vô hiệu hóa session
   */
  async invalidateSession(sessionId: string, reason: string = 'UNKNOWN'): Promise<void> {
    await this.redisService.set(`session_invalidated:${sessionId}`, reason, 'EX', 30 * 24 * 60 * 60)
  }

  /**
   * Kiểm tra session có bị vô hiệu hóa không
   */
  async isSessionInvalidated(sessionId: string): Promise<boolean> {
    const result = await this.redisService.exists(`session_invalidated:${sessionId}`)
    return result > 0
  }

  /**
   * Vô hiệu hóa tất cả session của user
   */
  invalidateAllUserSessions(
    userId: number,
    reason: string = 'UNKNOWN_BULK_INVALIDATION',
    sessionIdToExclude?: string
  ): void {
    // Trong môi trường thực tế, sẽ triển khai logic để vô hiệu hóa tất cả session của user
    this.logger.log(`Vô hiệu hóa tất cả session của user ${userId}, trừ session ${sessionIdToExclude}`)
  }
}
