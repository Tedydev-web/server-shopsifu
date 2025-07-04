import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'
import { v4 as uuidv4 } from 'uuid'

import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { REDIS_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'

import { ITokenService, ISLTService, SltContextData, SltJwtPayload } from 'src/routes/auth/auth.types'
import {
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  SLT_EXPIRY_SECONDS,
  SLT_MAX_ATTEMPTS
} from 'src/routes/auth/auth.constants'
import { AuthError } from 'src/routes/auth/auth.error'

@Injectable()
export class SLTService implements ISLTService {
  private readonly logger = new Logger(SLTService.name)

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly jwtService: JwtService
  ) {}

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

    // Handle registration flow with temporary IDs
    const isRegistrationFlow = purpose === TypeOfVerificationCode.REGISTER && userId === 0 && deviceId === 0
    if (isRegistrationFlow) {
      userId = this.generateTemporaryId()
      deviceId = this.generateTemporaryId()

      // Ensure email is stored in metadata for registration
      if (email && (!metadata || !metadata.pendingEmail)) {
        metadata = { ...metadata, pendingEmail: email }
      }
    }

    // Create new SLT token first
    const { sltToken, jti, exp, iat } = this.createSltToken(userId, purpose)

    // Prepare SLT context data
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

    // Atomic operation: cleanup old + store new
    await this.atomicReplaceActiveSltToken(userId, purpose, jti, sltContextData)

    return sltToken
  }

  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    try {
      const decodedToken = await this.verifyAndDecodeSltToken(sltCookieValue)
      const { jti, pur: purpose } = decodedToken

      if (expectedPurpose && purpose !== expectedPurpose) {
        throw AuthError.SLTInvalidPurpose()
      }

      const sltContext = await this.getSltContext(jti)
      await this.validateSltConstraints(sltContext, jti, currentIpAddress, currentUserAgent)

      return {
        ...sltContext,
        sltJti: jti
      }
    } catch (error) {
      if (error instanceof AuthError) {
        throw error
      }
      throw AuthError.SLTExpired()
    }
  }

  extractJtiFromToken(sltToken: string): string {
    const decodedToken = this.jwtService.decode(sltToken)
    if (!decodedToken || typeof decodedToken === 'string' || !decodedToken.jti) {
      throw AuthError.SLTExpired()
    }
    return decodedToken.jti
  }

  async updateSltContext(jti: string, updateData: Partial<SltContextData>): Promise<void> {
    const sltContextKey = this.getSltContextKey(jti)
    const updatePayload = this.prepareRedisUpdatePayload(updateData)

    if (Object.keys(updatePayload).length > 0) {
      await this.redisService.hset(sltContextKey, updatePayload)
    }
  }

  async finalizeSlt(sltJti: string): Promise<void> {
    try {
      // Get SLT context to extract userId and purpose for cleanup
      const sltContext = await this.getSltContext(sltJti)

      // Atomic cleanup: finalize context and remove active mapping
      await Promise.all([
        this.updateSltContext(sltJti, { finalized: '1' }),
        this.cleanupActiveTokenMapping(sltContext.userId, sltContext.purpose)
      ])
    } catch {
      // If context doesn't exist, just try to finalize what we can
      await this.updateSltContext(sltJti, { finalized: '1' })
    }
  }

  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this.getSltContextKey(sltJti)
    const newAttemptCount = await this.redisService.hincrby(sltContextKey, 'attempts', 1)
    return newAttemptCount
  }

  async hasActiveSltToken(userId: number, purpose: TypeOfVerificationCodeType): Promise<string | null> {
    const activeTokenKey = RedisKeyManager.getSltActiveTokenKey(userId, purpose)
    const activeJti = await this.redisService.get(activeTokenKey)

    if (activeJti) {
      const sltContextKey = this.getSltContextKey(activeJti)
      const exists = await this.redisService.exists(sltContextKey)

      if (exists) {
        return activeJti
      } else {
        // Context doesn't exist, cleanup stale mapping
        await this.redisService.del(activeTokenKey)
        return null
      }
    }

    return null
  }

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

    const sltToken = await this.createAndStoreSltToken({
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      email,
      metadata
    })

    return sltToken
  }

  private createSltToken(
    userId: number,
    purpose: TypeOfVerificationCodeType
  ): {
    sltToken: string
    jti: string
    exp: number
    iat: number
  } {
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
      throw AuthError.InternalServerError('Failed to decode SLT token for context.')
    }

    return {
      sltToken,
      jti,
      exp: decodedTokenPayload.exp,
      iat: decodedTokenPayload.iat
    }
  }

  private async verifyAndDecodeSltToken(sltToken: string): Promise<SltJwtPayload> {
    return await this.jwtService.verifyAsync<SltJwtPayload>(sltToken, {
      secret: this.configService.get('SLT_JWT_SECRET')
    })
  }

  private async storeSltContext(sltJti: string, sltContextData: SltContextData): Promise<void> {
    const sltContextKey = this.getSltContextKey(sltJti)
    const sltExpiry = this.getSltExpirySeconds()
    const sltContextForRedis = this.prepareSltContextForRedis(sltContextData)

    await this.redisService.hset(sltContextKey, sltContextForRedis)
    await this.redisService.expire(sltContextKey, sltExpiry)
  }

  private async getSltContext(jti: string): Promise<SltContextData> {
    const sltContextKey = this.getSltContextKey(jti)
    const redisContext = await this.redisService.hgetall(sltContextKey)

    if (!redisContext || Object.keys(redisContext).length === 0) {
      throw AuthError.SLTExpired()
    }

    return this.parseSltContextFromRedis(redisContext)
  }

  private async validateSltConstraints(
    sltContext: SltContextData,
    jti: string,
    currentIpAddress: string,
    currentUserAgent: string
  ): Promise<void> {
    // Check attempt count
    const currentAttempts = sltContext.attempts || 0
    const maxAttempts = this.configService.get('security.sltMaxAttempts', SLT_MAX_ATTEMPTS)
    if (currentAttempts >= maxAttempts) {
      const sltContextKey = this.getSltContextKey(jti)
      await this.redisService.del(sltContextKey)
      throw AuthError.SLTMaxAttemptsExceeded()
    }

    // Check finalized status
    if (sltContext.finalized === '1') {
      if (!(sltContext.purpose === TypeOfVerificationCode.REGISTER && sltContext.metadata?.otpVerified === 'true')) {
        throw AuthError.SLTAlreadyUsed()
      }
    }
  }

  private async storeActiveTokenMapping(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    jti: string,
    ttlSeconds: number
  ): Promise<void> {
    const activeTokenKey = RedisKeyManager.getSltActiveTokenKey(userId, purpose)
    await this.redisService.set(activeTokenKey, jti, 'EX', ttlSeconds)
  }

  private async cleanupActiveTokenMapping(userId: number, purpose: TypeOfVerificationCodeType): Promise<void> {
    const activeTokenKey = RedisKeyManager.getSltActiveTokenKey(userId, purpose)
    await this.redisService.del(activeTokenKey)
  }

  private async atomicReplaceActiveSltToken(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    newJti: string,
    sltContextData: SltContextData
  ): Promise<void> {
    const activeTokenKey = RedisKeyManager.getSltActiveTokenKey(userId, purpose)
    const newContextKey = this.getSltContextKey(newJti)
    const sltExpiry = this.getSltExpirySeconds()

    try {
      // Get existing JTI to cleanup (if any)
      const existingJti = await this.redisService.get(activeTokenKey)

      // Prepare context data for Redis
      const contextForRedis = this.prepareSltContextForRedis(sltContextData)

      if (existingJti) {
        // Step 1: Store new context first
        await this.redisService.hset(newContextKey, contextForRedis)
        await this.redisService.expire(newContextKey, sltExpiry)

        // Step 2: Update active mapping to point to new token
        await this.redisService.set(activeTokenKey, newJti, 'EX', sltExpiry)

        // Step 3: Clean up old context (safe to do after mapping is updated)
        const existingContextKey = this.getSltContextKey(existingJti)
        await this.redisService.del(existingContextKey)
      } else {
        // No existing token, just create new one
        await this.redisService.hset(newContextKey, contextForRedis)
        await this.redisService.expire(newContextKey, sltExpiry)
        await this.redisService.set(activeTokenKey, newJti, 'EX', sltExpiry)
      }
    } catch {
      // Rollback: Clean up any partially created data
      await this.redisService.del(newContextKey)

      throw AuthError.InternalServerError('Failed to store SLT token')
    }
  }

  private generateTemporaryId(): number {
    return -Math.floor(Math.random() * 1000000) - 1
  }

  private getSltExpirySeconds(): number {
    return this.configService.get<number>('security.sltExpirySeconds', SLT_EXPIRY_SECONDS)
  }

  private getSltContextKey(jti: string): string {
    return RedisKeyManager.getSltContextKey(jti)
  }

  private prepareSltContextForRedis(sltContextData: SltContextData): Record<string, string> {
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
      const metadataString =
        typeof sltContextData.metadata === 'object'
          ? JSON.stringify(sltContextData.metadata)
          : String(sltContextData.metadata)
      sltContextForRedis.metadata = metadataString
    }

    return sltContextForRedis
  }

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
      } catch {
        parsedContext.metadata = { value: redisContext.metadata }
      }
    }

    return parsedContext
  }

  private prepareRedisUpdatePayload(updateData: Partial<SltContextData>): Record<string, string> {
    const updatePayload: Record<string, string> = {}

    for (const [key, value] of Object.entries(updateData)) {
      if (value !== undefined && value !== null) {
        if (typeof value === 'object') {
          updatePayload[key] = JSON.stringify(value)
        } else {
          updatePayload[key] = String(value)
        }
      }
    }

    return updatePayload
  }
}
