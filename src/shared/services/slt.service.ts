import { Inject, Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { EnvConfigType } from 'src/shared/config'
import * as tokens from 'src/shared/constants/injection.tokens'
import { RedisKeyManager } from '../providers/redis/redis-key.manager'
import { IRedisService } from '../providers/redis/redis.interface'
import { v4 as uuidv4 } from 'uuid'
import { GlobalError } from 'src/shared/global.error'
import { extractRealIpFromRequest } from '../utils/http.utils'

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
  private readonly logger = new Logger(SltService.name)

  constructor(
    private readonly configService: ConfigService<EnvConfigType>,
    private readonly jwtService: JwtService,
    @Inject(tokens.REDIS_SERVICE) private readonly redisService: IRedisService,
  ) {}

  /**
   * Creates a new State-Linking Token and stores its context in Redis.
   */
  async createStateToken(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    req: Request,
    metadata?: Record<string, any>,
  ): Promise<string> {
    const jti = uuidv4()
    const sltSecret = this.configService.get('jwt').accessToken.secret // Reuse secret for now
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
      metadata,
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
    expectedPurpose: TypeOfVerificationCodeType,
  ): Promise<SltContextData> {
    const sltSecret = this.configService.get('jwt').accessToken.secret

    let payload: SltJwtPayload
    try {
      payload = this.jwtService.verify(token, { secret: sltSecret })
    } catch (error) {
      throw GlobalError.Unauthorized('Invalid or expired state token.')
    }

    if (payload.purpose !== expectedPurpose) {
      throw GlobalError.Forbidden('Invalid token purpose.')
    }

    const key = RedisKeyManager.getSltContextKey(payload.jti)
    const context = await this.redisService.get<SltContextData>(key)

    if (!context) {
      throw GlobalError.Unauthorized('State context not found or expired.')
    }

    const ip = extractRealIpFromRequest(req)
    // Security check: Match IP and User-Agent
    if (context.ipAddress !== ip || context.userAgent !== (req.headers['user-agent'] || '')) {
      // If mismatch, invalidate the context immediately as a security measure
      await this.redisService.del(key)
      throw GlobalError.Forbidden('Client environment mismatch. Possible session hijacking attempt.')
    }

    return context
  }
}
