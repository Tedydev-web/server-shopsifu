import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import {
  TokenType,
  TokenTypeType,
  TypeOfVerificationCode,
  TypeOfVerificationCodeType
} from '../constants/auth.constants'
import envConfig from 'src/shared/config'
import { EmailService } from './email.service'
import { addMilliseconds } from 'date-fns'
import ms from 'ms'
import { v4 as uuidv4 } from 'uuid'
import { generateOTP } from 'src/routes/auth/utils/otp.utils'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import {
  InvalidOTPException,
  OTPExpiredException,
  FailedToSendOTPException,
  InvalidOTPTokenException,
  OTPTokenExpiredException,
  DeviceMismatchException,
  TooManyOTPAttemptsException
} from 'src/routes/auth/auth.error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { JwtService } from '@nestjs/jwt'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'

interface OtpData {
  code: string
  attempts: number
  createdAt: number // Unix timestamp in milliseconds
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
}

export interface VerificationJwtPayload {
  jti: string
  sub: string // email
  type: TypeOfVerificationCodeType
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
  iat: number
  exp: number
}

// Define SLT Context and Payload
interface SltJwtPayload {
  jti: string
  sub?: number // userId, optional for anonymous flows like registration
  pur: TypeOfVerificationCodeType // purpose
  iat?: number // Optional: Issued at, jwtService will add this
  exp?: number // Optional: Expiration time, jwtService will add this
}

export interface SltContextData {
  userId?: number // userId is optional for anonymous flows like registration before user exists
  deviceId?: number
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  finalized: '0' | '1'
  email?: string // For anonymous flows, email is stored here
  metadata?: Record<string, any>
}

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name)
  private readonly MAX_OTP_ATTEMPTS = 5

  constructor(
    private readonly prismaService: PrismaService,
    private readonly emailService: EmailService,
    private readonly i18nService: I18nService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    private readonly auditLogService: AuditLogService
  ) {}

  private _getOtpKey(type: TypeOfVerificationCodeType, identifier: string): string {
    return `${REDIS_KEY_PREFIX.OTP_CODE}${type}:${identifier}`
  }

  private _getVerificationJwtPayloadKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.VERIFICATION_JWT_PAYLOAD}${jti}`
  }

  private _getVerificationJwtBlacklistKey(jti: string): string {
    // Consider renaming or creating a new prefix if this is purely for old verification JWTs
    return `${REDIS_KEY_PREFIX.VERIFICATION_JWT_BLACKLIST_JTI}${jti}`
  }

  private _getSltContextKey(jti: string): string {
    return `${REDIS_KEY_PREFIX.SLT_CONTEXT}${jti}`
  }

  async sendOTP(
    email: string,
    type: TypeOfVerificationCodeType,
    userIdForOtpData?: number
  ): Promise<{ message: string }> {
    const otpKey = this._getOtpKey(type, email)
    const code = generateOTP()
    const otpTTLSeconds = Math.floor(ms(envConfig.OTP_EXPIRES_IN) / 1000)

    const otpData: OtpData = {
      code,
      attempts: 0,
      createdAt: Date.now(),
      userId: userIdForOtpData // Store userId with OTP data if available and relevant
    }

    await this.redisService.set(otpKey, JSON.stringify(otpData), otpTTLSeconds)
    this.logger.debug(`OTP for ${type} for ${email} stored in Redis with TTL ${otpTTLSeconds}s. Key: ${otpKey}`)

    let title: string
    const lang = I18nContext.current()?.lang || 'en'

    switch (type) {
      case TypeOfVerificationCode.REGISTER:
        title = this.i18nService.translate('email.OTPSubject.Register', { lang })
        break
      case TypeOfVerificationCode.RESET_PASSWORD:
        title = this.i18nService.translate('email.OTPSubject.ResetPassword', { lang })
        break
      case TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP:
        title = this.i18nService.translate('email.OTPSubject.LoginUntrustedDevice', { lang })
        break
      case TypeOfVerificationCode.LOGIN_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      case TypeOfVerificationCode.DISABLE_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      case TypeOfVerificationCode.SETUP_2FA:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
        break
      default:
        title = this.i18nService.translate('email.OTPSubject.Default', { lang })
    }

    try {
      await this.emailService.sendOTP({ email, code, title })
      this.auditLogService.recordAsync({
        userEmail: email,
        action: 'OTP_SENT',
        status: AuditLogStatus.SUCCESS,
        details: { type, emailSent: true } as Prisma.JsonObject
      })
      return { message: 'Auth.Otp.SentSuccessfully' }
    } catch (error) {
      this.logger.error(`Failed to send OTP to ${email} for type ${type}`, error)
      this.auditLogService.recordAsync({
        userEmail: email,
        action: 'OTP_SEND_FAILED',
        status: AuditLogStatus.FAILURE,
        errorMessage: error.message,
        details: { type } as Prisma.JsonObject
      })
      throw FailedToSendOTPException
    }
  }

  async verifyOTPAndCreateToken(payload: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
    userId?: number
    deviceId?: number
    metadata?: Record<string, any>
    ip?: string
    userAgent?: string
  }): Promise<string> {
    const { otpKey, otpData } = await this._verifyOtpCore(
      payload.email,
      payload.code,
      payload.type,
      payload.ip,
      payload.userAgent
    )
    // If OTP is valid, otpData is returned and otpKey is deleted by _verifyOtpCore

    const jwtJti = uuidv4()
    const nowSeconds = Math.floor(Date.now() / 1000)
    const expiresInSeconds = Math.floor(ms(envConfig.VERIFICATION_JWT_EXPIRES_IN) / 1000)

    const verificationJwtPayload: VerificationJwtPayload = {
      jti: jwtJti,
      sub: payload.email,
      type: payload.type,
      userId: payload.userId,
      deviceId: payload.deviceId,
      metadata: payload.metadata,
      iat: nowSeconds,
      exp: nowSeconds + expiresInSeconds
    }

    const verificationJwt = this.jwtService.sign(verificationJwtPayload, {
      secret: envConfig.VERIFICATION_JWT_SECRET,
      expiresIn: envConfig.VERIFICATION_JWT_EXPIRES_IN
    })

    await this.redisService.set(
      this._getVerificationJwtPayloadKey(jwtJti),
      JSON.stringify(verificationJwtPayload),
      expiresInSeconds
    )
    this.logger.debug(
      `Verification JWT payload for JTI ${jwtJti} stored in Redis. Key: ${this._getVerificationJwtPayloadKey(jwtJti)}`
    )

    this.auditLogService.recordAsync({
      userEmail: payload.email,
      action: 'OTP_VERIFY_SUCCESS_JWT_CREATED',
      userId: payload.userId,
      status: AuditLogStatus.SUCCESS,
      details: { ...otpData, verificationJwtJti: jwtJti } as Prisma.JsonObject
    })

    return verificationJwt
  }

  // New method to only verify OTP
  async verifyOtpOnly(
    email: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userId?: number, // For audit logging
    ip?: string,
    userAgent?: string
  ): Promise<boolean> {
    await this._verifyOtpCore(email, code, type, ip, userAgent, userId)
    return true // If _verifyOtpCore doesn't throw, OTP is valid
  }

  // Internal core OTP verification logic, extracted from verifyOTPAndCreateToken
  private async _verifyOtpCore(
    email: string,
    code: string,
    type: TypeOfVerificationCodeType,
    ip?: string,
    userAgent?: string,
    userIdForAudit?: number // Optional userId for more specific auditing
  ): Promise<{ otpKey: string; otpData: OtpData }> {
    const otpKey = this._getOtpKey(type, email)
    const otpDataString = await this.redisService.get(otpKey)

    const auditDetailsBase: Record<string, any> = {
      email: email,
      type: type,
      otpProvided: code,
      ip: ip,
      userAgent: userAgent,
      userId: userIdForAudit // Include userId in audit if provided
    }

    if (!otpDataString) {
      this.logger.warn(`OTP verification failed: No OTP data found for key ${otpKey}`)
      this.auditLogService.recordAsync({
        userEmail: email,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'OTP_EXPIRED_OR_NOT_FOUND',
        details: auditDetailsBase as Prisma.JsonObject
      })
      throw OTPExpiredException
    }

    const otpData: OtpData = JSON.parse(otpDataString)

    if (otpData.attempts >= this.MAX_OTP_ATTEMPTS) {
      this.logger.warn(`OTP verification failed: Max attempts reached for key ${otpKey}`)
      await this.redisService.del(otpKey) // Delete on max attempts
      this.auditLogService.recordAsync({
        userEmail: email,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'MAX_OTP_ATTEMPTS_REACHED',
        details: { ...auditDetailsBase, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw TooManyOTPAttemptsException
    }

    if (otpData.code !== code) {
      otpData.attempts += 1
      const ttl = await this.redisService.ttl(otpKey)
      if (ttl > 0) {
        await this.redisService.set(otpKey, JSON.stringify(otpData), ttl)
      }
      this.logger.warn(
        `OTP verification failed: Invalid code for key ${otpKey}. Attempt ${otpData.attempts}/${this.MAX_OTP_ATTEMPTS}`
      )
      this.auditLogService.recordAsync({
        userEmail: email,
        userId: userIdForAudit,
        action: 'OTP_VERIFY_FAIL',
        status: AuditLogStatus.FAILURE,
        errorMessage: 'INVALID_OTP_CODE',
        details: { ...auditDetailsBase, attempts: otpData.attempts } as Prisma.JsonObject
      })
      throw InvalidOTPException
    }

    await this.redisService.del(otpKey) // OTP verified, delete it.
    this.logger.debug(`OTP for key ${otpKey} verified and deleted from Redis.`)

    // Audit success for OTP verification part
    this.auditLogService.recordAsync({
      userEmail: email,
      userId: userIdForAudit,
      action: 'OTP_VERIFY_ONLY_SUCCESS',
      status: AuditLogStatus.SUCCESS,
      details: { ...auditDetailsBase, type } as Prisma.JsonObject
    })
    return { otpKey, otpData }
  }

  async initiateOtpWithSltCookie(payload: {
    email: string
    userId: number // For known user flows
    deviceId?: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    metadata?: Record<string, any>
  }): Promise<string> {
    const { email, userId, deviceId, ipAddress, userAgent, purpose, metadata } = payload
    const sltJti = uuidv4()

    const sltPayload: SltJwtPayload = {
      jti: sltJti,
      sub: userId,
      pur: purpose
    }

    const sltJwt = this.jwtService.sign(sltPayload, {
      secret: envConfig.SLT_JWT_SECRET,
      expiresIn: envConfig.SLT_JWT_EXPIRES_IN
    })

    const sltContextData: SltContextData = {
      userId,
      deviceId,
      ipAddress,
      userAgent,
      purpose,
      finalized: '0',
      email,
      metadata
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextTtlSeconds = Math.max(
      Math.floor(ms(envConfig.SLT_JWT_EXPIRES_IN) / 1000) + 60, // Context lives 60s longer than JWT
      60
    )

    await this.redisService.setJson(sltContextKey, sltContextData, sltContextTtlSeconds)
    this.logger.debug(
      `SLT context for JTI ${sltJti} (purpose ${purpose}, email ${email}) stored in Redis with TTL ${sltContextTtlSeconds}s. Key: ${sltContextKey}`
    )
    this.auditLogService.recordAsync({
      userId,
      userEmail: email,
      action: 'SLT_CONTEXT_CREATED',
      status: AuditLogStatus.SUCCESS,
      ipAddress,
      userAgent,
      details: {
        sltJti,
        purpose,
        deviceId,
        sltContextKey,
        sltContextTtlSeconds
      } as Prisma.JsonObject
    })

    return sltJwt
  }

  async validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    const auditLogDetails: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'SLT_VALIDATION_ATTEMPT',
      ipAddress: currentIpAddress,
      userAgent: currentUserAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        sltCookieProvided: !!sltCookieValue,
        expectedPurpose: expectedPurpose || 'ANY'
      }
    }

    if (!sltCookieValue) {
      auditLogDetails.errorMessage = 'SLT cookie is missing.'
      auditLogDetails.details.reason = 'SLT_COOKIE_MISSING'
      this.auditLogService.recordAsync(auditLogDetails as AuditLogData)
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.OtpToken.Invalid', {
        path: 'slt_token',
        code: 'Error.Auth.OtpToken.Invalid'
      })
    }

    let decodedSltJwt: SltJwtPayload & { exp: number; iat: number }
    try {
      decodedSltJwt = await this.jwtService.verifyAsync<SltJwtPayload & { exp: number; iat: number }>(sltCookieValue, {
        secret: envConfig.SLT_JWT_SECRET,
        ignoreExpiration: false
      })
    } catch (error) {
      auditLogDetails.errorMessage = `SLT JWT verification failed: ${error.message}`
      auditLogDetails.details.reason = 'SLT_JWT_VERIFICATION_FAILED'
      auditLogDetails.details.jwtError = error.name
      this.auditLogService.recordAsync(auditLogDetails as AuditLogData)
      const errPath = 'slt_token'
      if (error.name === 'TokenExpiredError') {
        throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.OtpToken.Expired', {
          path: errPath,
          code: 'Error.Auth.OtpToken.Expired'
        })
      }
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.OtpToken.Invalid', {
        path: errPath,
        code: 'Error.Auth.OtpToken.Invalid'
      })
    }

    const sltJti = decodedSltJwt.jti
    auditLogDetails.details.sltJti = sltJti
    if (decodedSltJwt.sub) auditLogDetails.userId = decodedSltJwt.sub

    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextData = await this.redisService.getJson<SltContextData>(sltContextKey)

    if (!sltContextData) {
      auditLogDetails.errorMessage = `SLT context not found in Redis for JTI ${sltJti}.`
      auditLogDetails.details.reason = 'SLT_CONTEXT_NOT_FOUND_OR_EXPIRED_IN_REDIS'
      this.auditLogService.recordAsync(auditLogDetails as AuditLogData)
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', {
        path: 'slt_token',
        code: 'Error.Auth.Session.InvalidLogin'
      })
    }
    auditLogDetails.details.contextPurpose = sltContextData.purpose
    if (sltContextData.email) auditLogDetails.userEmail = sltContextData.email

    if (sltContextData.finalized === '1') {
      auditLogDetails.errorMessage = `SLT context for JTI ${sltJti} has already been finalized.`
      auditLogDetails.details.reason = 'SLT_CONTEXT_ALREADY_FINALIZED'
      this.auditLogService.recordAsync(auditLogDetails as AuditLogData)
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', {
        path: 'slt_token',
        code: 'Error.Auth.Session.InvalidLogin'
      })
    }

    if (expectedPurpose && sltContextData.purpose !== expectedPurpose) {
      auditLogDetails.errorMessage = `SLT purpose mismatch for JTI ${sltJti}. Expected: ${expectedPurpose}, Actual: ${sltContextData.purpose}`
      auditLogDetails.details.reason = 'SLT_PURPOSE_MISMATCH'
      this.auditLogService.recordAsync(auditLogDetails as AuditLogData)
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'AuthenticationError', 'Error.Auth.Session.InvalidLogin', {
        path: 'slt_token',
        code: 'Error.Auth.Session.InvalidLogin'
      })
    }

    if (sltContextData.ipAddress !== currentIpAddress) {
      this.logger.warn(
        `SLT IP address mismatch for JTI ${sltJti}. Context IP: ${sltContextData.ipAddress}, Request IP: ${currentIpAddress}`
      )
      auditLogDetails.details.ipMismatch = `Context: ${sltContextData.ipAddress}, Request: ${currentIpAddress}`
    }

    if (sltContextData.userAgent !== currentUserAgent) {
      this.logger.warn(
        `SLT User-Agent mismatch for JTI ${sltJti}. Context UA: ${sltContextData.userAgent}, Request UA: ${currentUserAgent}`
      )
      auditLogDetails.details.userAgentMismatch = `Context: ${sltContextData.userAgent}, Request: ${currentUserAgent}`
    }

    auditLogDetails.status = AuditLogStatus.SUCCESS
    auditLogDetails.action = 'SLT_VALIDATION_SUCCESS'
    this.auditLogService.recordAsync(auditLogDetails as AuditLogData)

    return { ...sltContextData, sltJti }
  }

  async finalizeSlt(sltJti: string): Promise<void> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const result = await this.redisService.del(sltContextKey) // Delete the context key
    if (result > 0) {
      this.logger.debug(`SLT context for JTI ${sltJti} finalized and deleted from Redis.`)
      this.auditLogService.recordAsync({
        action: 'SLT_CONTEXT_FINALIZED',
        status: AuditLogStatus.SUCCESS,
        details: { sltJti, sltContextKey } as Prisma.JsonObject
      })
    } else {
      this.logger.warn(
        `Attempted to finalize SLT context for JTI ${sltJti}, but key was not found or already deleted. Key: ${sltContextKey}`
      )
      // Audit this too, as it might indicate a double finalization attempt or an issue.
      this.auditLogService.recordAsync({
        action: 'SLT_FINALIZE_WARN_NOT_FOUND',
        status: AuditLogStatus.FAILURE, // Or WARNING if such status exists
        errorMessage: 'SLT_CONTEXT_KEY_NOT_FOUND_ON_FINALIZE',
        details: { sltJti, sltContextKey } as Prisma.JsonObject
      })
    }
  }

  /**
   * @deprecated This method creates a short-lived JWT primarily for multi-step auth flows like 2FA.
   * It's being replaced by the State-Linking Token (SLT) mechanism.
   * Use initiateOtpWithSltCookie for new flows requiring an OTP step followed by verification.
   */
  createLoginSessionToken(payload: {
    email: string
    type: TypeOfVerificationCodeType
    userId: number
    deviceId: number
    metadata?: Record<string, any>
    tx?: PrismaTransactionClient // tx is not used here, Redis operations are separate
  }): Promise<string> {
    this.logger.warn(
      `[OtpService] createLoginSessionToken is deprecated and will be removed. Use SLT mechanism. Called for: ${payload.email}, type: ${payload.type}`
    )
    const { email, type, userId, deviceId, metadata } = payload
    const jti = uuidv4()
    const now = Math.floor(Date.now() / 1000)
    const expiresInSeconds = 5 * 60 // 5 minutes for login session token
    const expiresAt = now + expiresInSeconds

    const tokenPayload: VerificationJwtPayload = {
      jti,
      sub: email,
      type,
      userId,
      deviceId,
      metadata,
      iat: now,
      exp: expiresAt
    }
    // Store payload in Redis for potential detailed validation/revocation if needed later, though not strictly necessary for this type of token
    // await this.redisService.setJson(this._getVerificationJwtPayloadKey(jti), tokenPayload, expiresInSeconds)

    // jwtService.sign is synchronous by default
    const signedToken = this.jwtService.sign(tokenPayload, { secret: envConfig.VERIFICATION_JWT_SECRET })
    return Promise.resolve(signedToken) // Wrap in Promise.resolve to match return type
  }

  async blacklistVerificationToken(
    jti: string,
    currentTimestamp: number,
    expiresAtTimestamp: number,
    tx?: PrismaTransactionClient
  ): Promise<void> {
    // tx is not used here as Redis operations are typically outside DB transactions
    this.logger.warn(
      `[OtpService] blacklistVerificationToken is part of an older OTP flow. Called for JTI: ${jti}. Consider SLT finalization for new flows.`
    )
    const blacklistKey = this._getVerificationJwtBlacklistKey(jti)
    const ttl = expiresAtTimestamp - currentTimestamp
    if (ttl > 0) {
      await this.redisService.set(blacklistKey, 'blacklisted', ttl)
      this.logger.debug(`Blacklisted verification token JTI: ${jti} for ${ttl} seconds.`)
    }
  }

  async validateVerificationToken(
    token: string,
    expectedType: TypeOfVerificationCodeType,
    expectedEmail?: string,
    expectedDeviceId?: number
    // tx is not used here
  ): Promise<VerificationJwtPayload> {
    this.logger.warn(
      `[OtpService] validateVerificationToken is part of an older OTP flow. Called for token (type ${expectedType}). Consider SLT validation for new flows.`
    )
    let payload: VerificationJwtPayload
    try {
      payload = this.jwtService.verify<VerificationJwtPayload>(token, { secret: envConfig.VERIFICATION_JWT_SECRET })
    } catch (error) {
      this.logger.warn(`
        Failed to verify old verification token: ${error.message}.
        Token: ${token.substring(0, 20)}...
        Expected Type: ${expectedType}
      `)
      throw InvalidOTPTokenException // Re-throw as specific exception
    }

    const blacklistKey = this._getVerificationJwtBlacklistKey(payload.jti)
    if (await this.redisService.exists(blacklistKey)) {
      this.logger.warn(`Attempt to use blacklisted verification token JTI: ${payload.jti}`)
      throw OTPTokenExpiredException // Or a more specific "already used" exception
    }

    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) {
      this.logger.warn(`Old verification token expired: JTI ${payload.jti}, EXP ${payload.exp}, NOW ${now}`)
      throw OTPTokenExpiredException
    }

    if (payload.type !== expectedType) {
      this.logger.warn(
        `Old verification token type mismatch: JTI ${payload.jti}, Expected ${expectedType}, Got ${payload.type}`
      )
      throw InvalidOTPTokenException
    }

    if (expectedEmail && payload.sub !== expectedEmail) {
      this.logger.warn(
        `Old verification token email mismatch: JTI ${payload.jti}, Expected ${expectedEmail}, Got ${payload.sub}`
      )
      throw InvalidOTPTokenException
    }

    if (expectedDeviceId && payload.deviceId !== expectedDeviceId) {
      this.logger.warn(
        `Old verification token deviceId mismatch: JTI ${payload.jti}, Expected ${expectedDeviceId}, Got ${payload.deviceId}`
      )
      throw DeviceMismatchException
    }

    // Optional: Validate against stored payload in Redis if it exists (though createLoginSessionToken does not store it)
    // const storedPayloadString = await this.redisService.get(this._getVerificationJwtPayloadKey(payload.jti));
    // if (storedPayloadString) { ... compare ... }

    return payload
  }

  async sendOtpAndInitiateSltForAnonymous(payload: {
    email: string
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCode.REGISTER | TypeOfVerificationCode.RESET_PASSWORD
    metadata?: Record<string, any>
  }): Promise<string> {
    const { email, ipAddress, userAgent, purpose, metadata } = payload
    const sltJti = uuidv4()

    const sltPayload: SltJwtPayload = {
      jti: sltJti,
      pur: purpose
    }

    const sltJwt = this.jwtService.sign(sltPayload, {
      secret: envConfig.SLT_JWT_SECRET,
      expiresIn: envConfig.SLT_JWT_EXPIRES_IN
    })

    const sltContextData: SltContextData = {
      ipAddress,
      userAgent,
      purpose,
      finalized: '0',
      email,
      metadata
    }

    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextTtlSeconds = Math.max(
      Math.floor(ms(envConfig.SLT_JWT_EXPIRES_IN) / 1000) + 60, // Context lives 60s longer
      60
    )

    await this.redisService.setJson(sltContextKey, sltContextData, sltContextTtlSeconds)
    this.logger.debug(
      `Anonymous SLT context for JTI ${sltJti} (purpose ${purpose}, email ${email}) stored in Redis with TTL ${sltContextTtlSeconds}s. Key: ${sltContextKey}`
    )

    this.auditLogService.recordAsync({
      action: 'ANONYMOUS_SLT_INITIATED_WITH_OTP',
      status: AuditLogStatus.SUCCESS,
      userEmail: email,
      ipAddress: ipAddress,
      userAgent: userAgent,
      details: {
        sltJti,
        purpose,
        email,
        metadata,
        sltContextTtlSeconds
      } as Prisma.JsonObject
    })

    return sltJwt
  }

  async markSltOtpAsVerified(sltJti: string): Promise<boolean> {
    const sltContextKey = this._getSltContextKey(sltJti)
    const sltContextString = await this.redisService.get(sltContextKey)

    if (!sltContextString) {
      this.logger.warn(`Cannot mark OTP as verified: SLT context not found for JTI ${sltJti}. Key: ${sltContextKey}`)
      // Potentially throw an error or return false if context must exist
      return false
    }

    const sltContext: SltContextData = JSON.parse(sltContextString)

    if (sltContext.finalized === '1') {
      this.logger.warn(`Cannot mark OTP as verified for JTI ${sltJti}: SLT context is already finalized.`)
      return false // Or throw error
    }

    // Update metadata
    const updatedMetadata = {
      ...(sltContext.metadata || {}),
      otpVerified: '1'
    }
    const updatedContext: SltContextData = {
      ...sltContext,
      metadata: updatedMetadata
    }

    const ttl = await this.redisService.ttl(sltContextKey)
    if (ttl > 0) {
      await this.redisService.setJson(sltContextKey, updatedContext, ttl)
      this.logger.debug(`SLT context JTI ${sltJti} marked with otpVerified='1'. Key: ${sltContextKey}`)
      this.auditLogService.recordAsync({
        action: 'SLT_OTP_MARKED_VERIFIED',
        status: AuditLogStatus.SUCCESS,
        userEmail: sltContext.email,
        userId: sltContext.userId !== null ? sltContext.userId : undefined, // Handle potential null userId
        ipAddress: sltContext.ipAddress,
        userAgent: sltContext.userAgent,
        details: {
          sltJti,
          purpose: sltContext.purpose
        } as Prisma.JsonObject
      })
      return true
    } else {
      this.logger.warn(
        `SLT context for JTI ${sltJti} has expired or has no TTL. Cannot mark OTP as verified. Key: ${sltContextKey}`
      )
      return false
    }
  }
}
