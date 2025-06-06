import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/providers/redis/redis.service'
import { REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService, ISLTService, SltContextData, SltJwtPayload } from 'src/routes/auth/shared/auth.types'
import {
  TypeOfVerificationCodeType,
  SLT_EXPIRY_SECONDS,
  SLT_MAX_ATTEMPTS
} from 'src/routes/auth/shared/constants/auth.constants'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { AuthError } from 'src/routes/auth/auth.error'
import { v4 as uuidv4 } from 'uuid'
import { TypeOfVerificationCode } from 'src/routes/auth/shared/constants/auth.constants'

@Injectable()
export class SLTService implements ISLTService {
  private readonly logger = new Logger(SLTService.name)

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly jwtService: JwtService
  ) {}

  /**
   * Tạo và lưu SLT token
   */
  async createAndStoreSltToken(payload: {
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    email?: string
    metadata?: Record<string, any>
  }): Promise<string> {
    let { userId, deviceId } = payload
    const { ipAddress, userAgent, purpose, email } = payload
    let { metadata } = payload

    // Tạo userId và deviceId tạm thời cho luồng đăng ký nếu giá trị bằng 0
    const isRegistrationFlow = purpose === TypeOfVerificationCode.REGISTER && userId === 0 && deviceId === 0
    if (isRegistrationFlow) {
      // Tạo một userId tạm thời dạng âm để không xung đột với userId thật
      userId = -Math.floor(Math.random() * 1000000) - 1
      deviceId = -Math.floor(Math.random() * 1000000) - 1

      this.logger.debug(`[createAndStoreSltToken] Tạo userId tạm (${userId}) và deviceId tạm (${deviceId}) cho đăng ký`)

      // Đảm bảo email được lưu trong metadata cho quá trình đăng ký
      if (email && (!metadata || !metadata.pendingEmail)) {
        metadata = { ...metadata, pendingEmail: email }
      }
    }

    const jti = uuidv4()
    const sltPayload: SltJwtPayload = {
      jti,
      sub: userId,
      pur: purpose
    }

    const sltToken = this.tokenService.signShortLivedToken(sltPayload)

    const decodedTokenPayload = this.jwtService.decode(sltToken)
    if (
      !decodedTokenPayload ||
      typeof decodedTokenPayload === 'string' ||
      typeof decodedTokenPayload.exp !== 'number' ||
      typeof decodedTokenPayload.iat !== 'number'
    ) {
      this.logger.error('[createAndStoreSltToken] Invalid SLT token payload after decoding.')
      throw AuthError.InternalServerError('Failed to decode SLT token for context.')
    }
    const exp = decodedTokenPayload.exp
    const iat = decodedTokenPayload.iat

    const sltContextData: SltContextData = {
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      sltJwtExp: exp,
      sltJwtCreatedAt: iat,
      finalized: '0',
      attempts: 0,
      metadata,
      email,
      createdAt: new Date()
    }

    await this.storeSltContext(jti, sltContextData)

    this.logger.log(
      `[createAndStoreSltToken] Tạo SLT token cho ${isRegistrationFlow ? 'đăng ký với email ' + email : 'user ID ' + userId}, device ID ${deviceId}, purpose ${purpose}`
    )

    return sltToken
  }

  /**
   * Lưu context của SLT vào Redis
   */
  private async storeSltContext(sltJti: string, sltContextData: SltContextData): Promise<void> {
    const sltContextKey = this.getSltContextKey(sltJti)
    const sltExpiry = this.configService.get<number>('security.sltExpirySeconds', SLT_EXPIRY_SECONDS)

    const sltContextForRedis: Record<string, string> = {
      userId: String(sltContextData.userId),
      deviceId: String(sltContextData.deviceId),
      ipAddress: sltContextData.ipAddress,
      userAgent: sltContextData.userAgent,
      purpose: sltContextData.purpose,
      finalized: sltContextData.finalized || '0',
      attempts: String(sltContextData.attempts || 0),
      createdAt: sltContextData.createdAt ? sltContextData.createdAt.toISOString() : new Date().toISOString()
    }

    if (sltContextData.sltJwtExp) {
      sltContextForRedis.sltJwtExp = String(sltContextData.sltJwtExp)
    }
    if (sltContextData.sltJwtCreatedAt) {
      sltContextForRedis.sltJwtCreatedAt = String(sltContextData.sltJwtCreatedAt)
    }
    if (sltContextData.email) {
      sltContextForRedis.email = sltContextData.email
    }
    if (sltContextData.metadata) {
      sltContextForRedis.metadata =
        typeof sltContextData.metadata === 'object'
          ? JSON.stringify(sltContextData.metadata)
          : String(sltContextData.metadata)
    }

    await this.redisService.hset(sltContextKey, sltContextForRedis)
    await this.redisService.expire(sltContextKey, sltExpiry)
  }

  /**
   * Xác thực SLT từ cookie và lấy context
   */
  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    try {
      const decodedToken = await this.jwtService.verifyAsync<SltJwtPayload>(sltCookieValue, {
        secret: this.configService.get('SLT_JWT_SECRET')
      })

      const { jti, sub: userId, pur: purpose } = decodedToken

      if (expectedPurpose && purpose !== expectedPurpose) {
        this.logger.warn(
          `[validateSltFromCookieAndGetContext] SLT purpose mismatch: expected ${expectedPurpose}, got ${purpose}`
        )
        throw AuthError.SLTInvalidPurpose()
      }

      const sltContextKey = this.getSltContextKey(jti)
      const redisContext = await this.redisService.hgetall(sltContextKey)

      if (!redisContext || Object.keys(redisContext).length === 0) {
        this.logger.warn(`[validateSltFromCookieAndGetContext] SLT context not found for jti: ${jti}`)
        throw AuthError.SLTExpired()
      }

      // Xử lý đặc biệt cho quy trình đăng ký
      // Nếu SLT đã finalized nhưng là quy trình đăng ký và đã xác minh OTP
      // thì vẫn cho phép sử dụng để hoàn tất quá trình đăng ký
      const sltContext = this.parseSltContextFromRedis(redisContext)

      if (redisContext.finalized === '1') {
        if (purpose === TypeOfVerificationCode.REGISTER && sltContext.metadata?.otpVerified === 'true') {
          this.logger.log(
            `[validateSltFromCookieAndGetContext] Allowing reuse of finalized SLT for registration completion: ${jti}`
          )
        } else {
          this.logger.warn(`[validateSltFromCookieAndGetContext] SLT already used for jti: ${jti}`)
          throw AuthError.SLTAlreadyUsed()
        }
      }

      const currentAttempts = await this.incrementSltAttempts(jti)
      const maxAttempts = this.configService.get('security.sltMaxAttempts', SLT_MAX_ATTEMPTS)
      if (currentAttempts > maxAttempts) {
        this.logger.warn(`[validateSltFromCookieAndGetContext] SLT max attempts exceeded for jti: ${jti}`)
        await this.redisService.del(sltContextKey)
        throw AuthError.SLTMaxAttemptsExceeded()
      }

      if (sltContext.ipAddress !== currentIpAddress || sltContext.userAgent !== currentUserAgent) {
        this.logger.warn(
          `[validateSltFromCookieAndGetContext] IP or UserAgent mismatch for jti: ${jti}, userId: ${userId}`
        )
      }

      return {
        ...sltContext,
        sltJti: jti
      }
    } catch (error) {
      if (error instanceof AuthError) {
        throw error
      }
      this.logger.error(`[validateSltFromCookieAndGetContext] Error: ${error.message}`, error.stack)
      throw AuthError.SLTExpired()
    }
  }

  /**
   * Parse SLT context từ Redis
   */
  private parseSltContextFromRedis(redisContext: Record<string, string>): SltContextData {
    const parsedContext: SltContextData = {
      userId: parseInt(redisContext.userId, 10),
      deviceId: parseInt(redisContext.deviceId, 10),
      ipAddress: redisContext.ipAddress,
      userAgent: redisContext.userAgent,
      purpose: redisContext.purpose as TypeOfVerificationCodeType,
      finalized: redisContext.finalized as '0' | '1',
      attempts: parseInt(redisContext.attempts, 10) || 0
    }

    if (redisContext.sltJwtExp) {
      parsedContext.sltJwtExp = parseInt(redisContext.sltJwtExp, 10)
    }
    if (redisContext.sltJwtCreatedAt) {
      parsedContext.sltJwtCreatedAt = parseInt(redisContext.sltJwtCreatedAt, 10)
    }
    if (redisContext.email) {
      parsedContext.email = redisContext.email
    }
    if (redisContext.createdAt) {
      parsedContext.createdAt = new Date(redisContext.createdAt)
    }
    if (redisContext.metadata) {
      try {
        parsedContext.metadata = JSON.parse(redisContext.metadata)
      } catch (e) {
        this.logger.warn(`[parseSltContextFromRedis] Failed to parse metadata: ${redisContext.metadata}`)
        parsedContext.metadata = { value: redisContext.metadata }
      }
    }
    return parsedContext
  }

  /**
   * Cập nhật SLT context
   */
  async updateSltContext(jti: string, updateData: Partial<SltContextData>): Promise<void> {
    const sltContextKey = this.getSltContextKey(jti)
    const exists = await this.redisService.exists(sltContextKey)
    if (!exists) {
      throw AuthError.SLTExpired()
    }

    const updateObj: Record<string, string> = {}
    for (const key in updateData) {
      if (Object.prototype.hasOwnProperty.call(updateData, key)) {
        const typedKey = key as keyof SltContextData
        const value = updateData[typedKey]

        if (value === undefined) continue
        if (value === null) {
          updateObj[key] = ''
          continue
        }

        if (typedKey === 'metadata' && typeof value === 'object') {
          updateObj[key] = JSON.stringify(value)
        } else if (value instanceof Date) {
          updateObj[key] = value.toISOString()
        } else if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
          updateObj[key] = String(value)
        } else if (typeof value === 'object') {
          this.logger.warn(`Unexpected object for SLT key ${key}. Using JSON.stringify.`)
          try {
            updateObj[key] = JSON.stringify(value)
          } catch (e) {
            this.logger.error(`Failed to stringify object for SLT key ${key}`, e)
            updateObj[key] = '[SerializationError]'
          }
        } else {
          this.logger.warn(`Unhandled type for SLT key ${key}: ${typeof value}. Using String().`)
          updateObj[key] = String(value)
        }
      }
    }

    if (Object.keys(updateObj).length > 0) {
      await this.redisService.hset(sltContextKey, updateObj)
    }
  }

  /**
   * Hoàn thành SLT
   */
  async finalizeSlt(sltJti: string): Promise<void> {
    await this.updateSltContext(sltJti, { finalized: '1' })
    this.logger.log(`[finalizeSlt] SLT finalized: ${sltJti}`)
  }

  /**
   * Tăng số lượt thử cho SLT
   */
  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this.getSltContextKey(sltJti)
    return this.redisService.hincrby(sltContextKey, 'attempts', 1)
  }

  /**
   * Tạo key cho Redis SLT context
   */
  private getSltContextKey(jti: string): string {
    return RedisKeyManager.getSltContextKey(jti)
  }

  /**
   * Khởi tạo OTP và lưu vào SLT Cookie
   */
  async initiateOtpWithSltCookie(payload: {
    email: string
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    metadata?: Record<string, any>
  }): Promise<string> {
    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload

    // Tạo và lưu SLT token
    const sltToken = await this.createAndStoreSltToken({
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      email,
      metadata
    })

    this.logger.log(`[initiateOtpWithSltCookie] SLT token created for user ${userId}, purpose: ${purpose}`)

    return sltToken
  }
}
