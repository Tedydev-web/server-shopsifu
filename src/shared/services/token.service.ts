import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'
import { Request } from 'express'
import { v4 as uuidv4 } from 'uuid'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import {
  ITokenService,
  AccessTokenPayload,
  AccessTokenPayloadCreate,
  PendingLinkTokenPayload,
  PendingLinkTokenPayloadCreate
} from 'src/shared/types/auth.types'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { AuthError } from 'src/routes/auth/auth.error'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'

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
      type: 'REFRESH',
      rememberMe
    }

    return Promise.resolve(this.signRefreshToken(payload))
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
      secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('auth.accessToken.expiresIn', '1h')
    })
  }

  /**
   * Tạo refresh token
   */
  signRefreshToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>): string {
    const expiresIn =
      payload.rememberMe === true
        ? this.configService.get('auth.refreshToken.extendedExpiresIn', '30d')
        : this.configService.get('auth.refreshToken.expiresIn', '7d')
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      expiresIn
    })
  }

  /**
   * Tạo Short-Lived Token
   */
  signShortLivedToken(payload: any): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('SLT_JWT_SECRET'),
      expiresIn: this.configService.get('SLT_JWT_EXPIRES_IN', '5m')
    })
  }

  /**
   * Xác minh access token
   */
  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET')
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
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET')
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
      secret: this.configService.get<string>('PENDING_LINK_TOKEN_SECRET'),
      expiresIn: this.configService.get('auth.pendingLinkToken.expiresIn', '15m')
    })
  }

  /**
   * Xác minh pending link token
   */
  async verifyPendingLinkToken(token: string): Promise<PendingLinkTokenPayload> {
    try {
      return await this.jwtService.verifyAsync<PendingLinkTokenPayload>(token, {
        secret: this.configService.get<string>('PENDING_LINK_TOKEN_SECRET')
      })
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
    try {
      const key = RedisKeyManager.getAccessTokenBlacklistKey(accessTokenJti)
      const now = Math.floor(Date.now() / 1000)
      const ttl = accessTokenExp - now

      if (ttl > 0) {
        await this.redisService.set(key, '1', 'EX', ttl)
      }
    } catch (error) {
      this.logger.error(`Lỗi khi đánh dấu access token là đã vô hiệu hóa: ${error.message}`, error.stack)
    }
  }

  /**
   * Đánh dấu refresh token là đã vô hiệu hóa
   */
  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
    const refreshTokenConfig = this.configService.get<any>('security.jwt.refresh')
    const ttlSeconds = refreshTokenConfig.expiresIn
    await this.redisService.set(key, sessionId, 'EX', ttlSeconds)
  }

  /**
   * Kiểm tra access token có trong blacklist không
   */
  async isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.getAccessTokenBlacklistKey(accessTokenJti)
    const result = await this.redisService.exists(key)
    return result === 1
  }

  /**
   * Kiểm tra refresh token có trong blacklist không
   */
  async isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
    const result = await this.redisService.exists(key)
    return result === 1
  }

  /**
   * Tìm session ID từ refresh token
   */
  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
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
    const key = RedisKeyManager.getRefreshTokenUsedKey(refreshTokenJti)
    const result = await this.redisService.set(key, sessionId, 'EX', ttlSeconds, 'NX')
    return result === 'OK'
  }
}
