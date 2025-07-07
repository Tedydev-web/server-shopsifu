import { Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import envConfig from 'src/shared/config'
import { RedisKeyManager } from '../providers/redis/redis-key.manager'
import { RedisService } from '../providers/redis/redis.service'
import { v4 as uuidv4 } from 'uuid'
import { UnauthorizedException, ForbiddenException } from 'src/shared/error'
import { extractRealIpFromRequest } from '../utils/http.utils'
import { I18nTranslations } from '../i18n/generated/i18n.generated'

export interface SltJwtPayload {
  jti: string
  sub: number // userId
  purpose: TypeOfVerificationCodeType
}

export interface SltContextData {
  userId: number
  purpose: TypeOfVerificationCodeType
  ipAddress: string
  userAgent: string
  createdAt: string
  attempts: number
  status: 'pending' | 'verified'
  metadata?: Record<string, any>
}

@Injectable()
export class SltService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService
  ) {}

  /**
   * Creates a new State-Linking Token and stores its context in Redis.
   */
  async createStateToken(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    req: Request,
    metadata?: Record<string, any>
  ): Promise<string> {
    const jti = uuidv4()
    const sltSecret = envConfig.ACCESS_TOKEN_SECRET // Reuse secret for now
    const sltExpiresIn = '15m' // Hardcode for now

    const token = this.jwtService.sign({ sub: userId, purpose, jti }, { secret: sltSecret, expiresIn: sltExpiresIn })

    const context: SltContextData = {
      userId,
      purpose,
      ipAddress: extractRealIpFromRequest(req),
      userAgent: req.headers['user-agent'] || '',
      createdAt: new Date().toISOString(),
      attempts: 0,
      status: 'pending',
      metadata
    }

    const key = RedisKeyManager.getSltContextKey(jti)
    await this.redisService.set(key, context, 15 * 60) // Expire in 15 minutes

    return token
  }

  /**
   * Validates an SLT and retrieves its context from Redis.
   * Throws an error if validation fails.
   */
  async validateAndGetContext(
    token: string,
    req: Request,
    expectedPurpose: TypeOfVerificationCodeType
  ): Promise<SltContextData> {
    const sltSecret = envConfig.ACCESS_TOKEN_SECRET

    let payload: SltJwtPayload
    try {
      payload = this.jwtService.verify(token, { secret: sltSecret })
    } catch (error) {
      throw UnauthorizedException
    }

    if (payload.purpose !== expectedPurpose) {
      throw ForbiddenException
    }

    const key = RedisKeyManager.getSltContextKey(payload.jti)
    const context = await this.redisService.get<SltContextData>(key)

    if (!context) {
      throw UnauthorizedException
    }

    const ip = extractRealIpFromRequest(req)
    // Security check: Match IP and User-Agent
    if (context.ipAddress !== ip || context.userAgent !== (req.headers['user-agent'] || '')) {
      // If mismatch, invalidate the context immediately as a security measure
      await this.redisService.del(key)
      throw ForbiddenException
    }

    return context
  }
}
