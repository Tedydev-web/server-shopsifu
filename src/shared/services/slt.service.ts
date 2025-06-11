import { Injectable, Logger, Inject } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ITokenService, ISLTService, SltContextData, SltJwtPayload } from 'src/routes/auth/auth.types'
import { TypeOfVerificationCodeType, SLT_EXPIRY_SECONDS, SLT_MAX_ATTEMPTS } from 'src/routes/auth/auth.constants'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { AuthError } from 'src/routes/auth/auth.error'
import { v4 as uuidv4 } from 'uuid'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'

@Injectable()
export class SLTService implements ISLTService {
  private readonly logger = new Logger(SLTService.name)

  constructor(
    private readonly configService: ConfigService,
    private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    private readonly jwtService: JwtService
  ) {}

  /**
   * Creates and stores a Short-Lived Token (SLT).
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

    // Create temporary userId and deviceId for registration flow if values are 0
    const isRegistrationFlow = purpose === TypeOfVerificationCode.REGISTER && userId === 0 && deviceId === 0
    if (isRegistrationFlow) {
      // Create a temporary negative userId to avoid conflicts with real userIds
      userId = -Math.floor(Math.random() * 1000000) - 1
      deviceId = -Math.floor(Math.random() * 1000000) - 1

      this.logger.debug(
        `[createAndStoreSltToken] Created temporary userId (${userId}) and deviceId (${deviceId}) for registration.`
      )

      // Ensure email is stored in metadata for the registration process
      if (email && (!metadata || !metadata.pendingEmail)) {
        metadata = { ...metadata, pendingEmail: email }
      }
    }

    // Check for existing SLT token for the same user and purpose
    // Skip for registration flow with temporary user IDs
    if (!isRegistrationFlow) {
      const existingJti = await this.findExistingSltToken(userId, purpose)
      if (existingJti) {
        this.logger.debug(
          `[createAndStoreSltToken] Found existing SLT token ${existingJti} for userId ${userId}, purpose ${purpose}. Deleting it.`
        )
        await this.deleteExistingSltToken(userId, purpose, existingJti)
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

    // Track the active token for duplicate prevention (skip for registration flow)
    if (!isRegistrationFlow) {
      const sltExpiry = this.configService.get<number>('security.sltExpirySeconds', SLT_EXPIRY_SECONDS)
      await this.trackActiveSltToken(userId, purpose, jti, sltExpiry)
    }

    this.logger.log(
      `[createAndStoreSltToken] Created SLT for ${isRegistrationFlow ? 'registration with email ' + email : 'user ID ' + userId}, device ID ${deviceId}, purpose ${purpose}`
    )

    return sltToken
  }

  /**
   * Stores the SLT context in Redis.
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
   * Validates the SLT from a cookie and retrieves its context.
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

      // Special handling for the registration process
      // If the SLT is finalized but it's a registration flow and OTP has been verified,
      // allow its use to complete the registration.
      const sltContext = this.parseSltContextFromRedis(redisContext)

      // Check attempt count before doing anything else
      const currentAttempts = sltContext.attempts || 0
      const maxAttempts = this.configService.get('security.sltMaxAttempts', SLT_MAX_ATTEMPTS)
      if (currentAttempts >= maxAttempts) {
        this.logger.warn(`[validateSltFromCookieAndGetContext] SLT max attempts exceeded for jti: ${jti}`)
        // Delete both the context and active token tracking to prevent further attempts
        const activeTokenKey = this.getSltActiveTokenKey(sltContext.userId, sltContext.purpose)
        await Promise.all([this.redisService.del(sltContextKey), this.redisService.del(activeTokenKey)])
        throw AuthError.SLTMaxAttemptsExceeded()
      }

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
   * Parses SLT context from a Redis hash.
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
      } catch {
        this.logger.warn(`[parseSltContextFromRedis] Failed to parse metadata: ${redisContext.metadata}`)
        parsedContext.metadata = { value: redisContext.metadata }
      }
    }
    return parsedContext
  }

  /**
   * Updates the SLT context
   */
  async updateSltContext(jti: string, updateData: Partial<SltContextData>): Promise<void> {
    const sltContextKey = this.getSltContextKey(jti)

    if (!(await this.redisService.exists(sltContextKey))) {
      this.logger.warn(`[updateSltContext] Attempted to update non-existent SLT context for jti: ${jti}`)
      throw AuthError.SLTExpired()
    }

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

    if (Object.keys(updatePayload).length > 0) {
      await this.redisService.hset(sltContextKey, updatePayload)
      this.logger.debug(
        `[updateSltContext] Updated SLT context for jti: ${jti} with keys: ${Object.keys(updatePayload).join(', ')}`
      )
    }
  }

  /**
   * Finalizes the SLT
   */
  async finalizeSlt(sltJti: string): Promise<void> {
    // Get the context to clean up active token tracking
    const sltContextKey = this.getSltContextKey(sltJti)
    const redisContext = await this.redisService.hgetall(sltContextKey)
    
    if (redisContext && Object.keys(redisContext).length > 0) {
      const sltContext = this.parseSltContextFromRedis(redisContext)
      
      // Clean up active token tracking (skip for registration flow with negative userIds)
      if (sltContext.userId > 0) {
        const activeTokenKey = this.getSltActiveTokenKey(sltContext.userId, sltContext.purpose)
        await this.redisService.del(activeTokenKey)
        this.logger.debug(
          `[finalizeSlt] Cleaned up active token tracking for userId ${sltContext.userId}, purpose ${sltContext.purpose}`
        )
      }
    }

    await this.updateSltContext(sltJti, { finalized: '1' })
    this.logger.log(`[finalizeSlt] Finalized SLT for jti: ${sltJti}`)
  }

  /**
   * Increments the SLT attempt count
   */
  async incrementSltAttempts(sltJti: string): Promise<number> {
    const sltContextKey = this.getSltContextKey(sltJti)
    const newAttemptCount = await this.redisService.hincrby(sltContextKey, 'attempts', 1)
    this.logger.debug(`[incrementSltAttempts] Incrementing attempt count for jti ${sltJti} to ${newAttemptCount}`)
    return newAttemptCount
  }

  /**
   * Creates a key for Redis SLT context
   */
  private getSltContextKey(jti: string): string {
    return RedisKeyManager.getSltContextKey(jti)
  }

  /**
   * Creates a key for tracking active SLT tokens by user and purpose
   */
  private getSltActiveTokenKey(userId: number, purpose: TypeOfVerificationCodeType): string {
    return RedisKeyManager.getSltActiveTokenKey(userId, purpose)
  }

  /**
   * Finds existing SLT token JTI for a user and purpose
   */
  private async findExistingSltToken(userId: number, purpose: TypeOfVerificationCodeType): Promise<string | null> {
    const activeTokenKey = this.getSltActiveTokenKey(userId, purpose)
    return await this.redisService.get(activeTokenKey)
  }

  /**
   * Deletes an existing SLT token and its tracking
   */
  private async deleteExistingSltToken(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    jti: string
  ): Promise<void> {
    const sltContextKey = this.getSltContextKey(jti)
    const activeTokenKey = this.getSltActiveTokenKey(userId, purpose)

    // Delete both the context and the active token tracking
    await Promise.all([this.redisService.del(sltContextKey), this.redisService.del(activeTokenKey)])

    this.logger.debug(
      `[deleteExistingSltToken] Deleted existing SLT token ${jti} for userId ${userId}, purpose ${purpose}`
    )
  }

  /**
   * Tracks an active SLT token for a user and purpose
   */
  private async trackActiveSltToken(
    userId: number,
    purpose: TypeOfVerificationCodeType,
    jti: string,
    expiry: number
  ): Promise<void> {
    const activeTokenKey = this.getSltActiveTokenKey(userId, purpose)
    await this.redisService.set(activeTokenKey, jti, 'EX', expiry)
  }

  /**
   * Initiates OTP and stores it in the SLT Cookie
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

    // Create and store SLT token
    const sltToken = await this.createAndStoreSltToken({
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      email,
      metadata
    })

    this.logger.log(`[initiateOtpWithSltCookie] Initiated OTP flow with SLT for ${email}, purpose: ${purpose}`)
    return sltToken
  }
}
