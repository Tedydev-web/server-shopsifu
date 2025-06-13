import { Inject, Injectable, Logger } from '@nestjs/common'
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
} from 'src/routes/auth/auth.types'
import { AuthError } from 'src/routes/auth/auth.error'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { REDIS_SERVICE } from '../constants/injection.tokens'

@Injectable()
export class TokenService implements ITokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    private readonly configService: ConfigService
  ) {}

  async generateAccessToken(userId: number): Promise<string> {
    const tokenJti = `access_${Date.now()}_${uuidv4().substring(0, 8)}`
    const payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> = {
      userId,
      jti: tokenJti,
      type: 'ACCESS'
    }
    return Promise.resolve(this.signAccessToken(payload))
  }

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

  async validateAccessToken(token: string): Promise<any> {
    try {
      return await this.verifyAccessToken(token)
    } catch {
      throw AuthError.InvalidAccessToken()
    }
  }

  async validateRefreshToken(token: string): Promise<any> {
    try {
      const payload = await this.verifyRefreshToken(token)

      // Kiểm tra token có bị blacklist không
      const isBlacklisted = await this.isRefreshTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidRefreshToken()
      }

      return payload
    } catch {
      throw AuthError.InvalidRefreshToken()
    }
  }

  signAccessToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
      expiresIn: this.configService.get('auth.accessToken.expiresIn', '1h')
    })
  }

  signRefreshToken(payload: Omit<AccessTokenPayloadCreate, 'exp' | 'iat'>): string {
    // Thời hạn token phụ thuộc vào rememberMe option
    const expiresIn =
      payload.rememberMe === true
        ? this.configService.get('auth.refreshToken.extendedExpiresIn', '30d')
        : this.configService.get('auth.refreshToken.expiresIn', '7d')
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      expiresIn
    })
  }

  signShortLivedToken(payload: any): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('SLT_JWT_SECRET'),
      expiresIn: this.configService.get('SLT_JWT_EXPIRES_IN', '5m')
    })
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET')
      })

      // Kiểm tra token có bị blacklist không
      const isBlacklisted = await this.isAccessTokenJtiBlacklisted(payload.jti)
      if (isBlacklisted) {
        throw AuthError.InvalidAccessToken()
      }

      return payload
    } catch (error) {
      if (error instanceof AuthError) throw error
      throw AuthError.InvalidAccessToken()
    }
  }

  async verifyRefreshToken(token: string): Promise<AccessTokenPayload> {
    try {
      const payload = await this.jwtService.verifyAsync<AccessTokenPayload>(token, {
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET')
      })

      return payload
    } catch (error) {
      if (error instanceof AuthError) throw error
      if (error.name === 'TokenExpiredError') {
        throw AuthError.RefreshTokenExpired()
      } else if (error.name === 'JsonWebTokenError') {
        throw AuthError.InvalidRefreshToken()
      }
      throw AuthError.InvalidRefreshToken()
    }
  }

  signPendingLinkToken(payload: PendingLinkTokenPayloadCreate): string {
    return this.jwtService.sign(payload, {
      secret: this.configService.get<string>('PENDING_LINK_TOKEN_SECRET'),
      expiresIn: this.configService.get('auth.pendingLinkToken.expiresIn', '15m')
    })
  }

  async verifyPendingLinkToken(token: string): Promise<PendingLinkTokenPayload> {
    try {
      return await this.jwtService.verifyAsync<PendingLinkTokenPayload>(token, {
        secret: this.configService.get<string>('PENDING_LINK_TOKEN_SECRET')
      })
    } catch {
      throw AuthError.InvalidPendingLinkToken()
    }
  }

  extractTokenFromRequest(req: Request): string | null {
    // Prioritize getting from Authorization header
    const authHeader = req.headers.authorization
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7)
    }

    // If not present, get from cookie
    return req.cookies?.access_token || null
  }

  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.refresh_token || null
  }

  async invalidateAccessTokenJti(accessTokenJti: string, accessTokenExp: number): Promise<void> {
    const key = RedisKeyManager.getAccessTokenBlacklistKey(accessTokenJti)
    const now = Math.floor(Date.now() / 1000)
    const ttl = accessTokenExp - now

    if (ttl > 0) {
      await this.redisService.set(key, '1', 'EX', ttl)
    }
  }

  async invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
    const refreshTokenConfig = this.configService.get<any>('security.jwt.refresh')
    const ttlSeconds = refreshTokenConfig.expiresIn
    await this.redisService.set(key, sessionId, 'EX', ttlSeconds)
  }

  async isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.getAccessTokenBlacklistKey(accessTokenJti)
    const result = await this.redisService.exists(key)
    return result === 1
  }

  async isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
    const result = await this.redisService.exists(key)
    return result === 1
  }

  async findSessionIdByRefreshTokenJti(refreshTokenJti: string): Promise<string | null> {
    const key = RedisKeyManager.getRefreshTokenBlacklistKey(refreshTokenJti)
    return this.redisService.get(key)
  }

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
